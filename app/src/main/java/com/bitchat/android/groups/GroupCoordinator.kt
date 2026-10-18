package com.bitchat.android.groups

import android.util.Log
import com.bitchat.android.protocol.BitchatPacket
import com.bitchat.android.protocol.MessageType
import com.bitchat.android.protocol.SpecialRecipients
import com.bitchat.android.model.NoisePayload
import com.bitchat.android.model.NoisePayloadType
import com.bitchat.android.util.AppConstants
import java.util.UUID

/**
 * Orchestrates creator-managed E2EE private groups over the existing mesh
 * transport, the Kotlin counterpart of bitchat-win's `MeshEngine` group
 * methods (`create_group`/`invite_to_group`/`remove_from_group`/
 * `send_group_message`/`_handle_group_message`/`_handle_group_state`).
 *
 * Deliberately transport-agnostic: everything peer/crypto/packet related
 * goes through [GroupCoordinatorDelegate] so this class is unit-testable
 * with a fake delegate, the same way bitchat-win's tests fake two
 * `MeshEngine`s wired directly together instead of real BLE.
 *
 * [groupManager] is nullable to mirror bitchat-win's "groups are disabled"
 * contract exactly: with no manager, every mutating call is a safe no-op
 * that returns a user-facing reason string instead of throwing.
 */
class GroupCoordinator(
    private val groupManager: GroupManager?,
    private val delegate: GroupCoordinatorDelegate
) {
    companion object {
        private const val TAG = "GroupCoordinator"
        private const val DISABLED_REASON = "groups are disabled"
        private val ALL_ZERO_KEY = ByteArray(GroupProtocolConstants.KEY_LENGTH)
    }

    fun listGroups(): List<BitchatGroup> = groupManager?.groups ?: emptyList()

    fun group(groupId: ByteArray): BitchatGroup? = groupManager?.group(groupId)

    fun createGroup(name: String): BitchatGroup? {
        val manager = groupManager ?: return null
        val creator = GroupMember(delegate.myFingerprint(), delegate.mySigningPublicKey(), delegate.myNickname())
        return manager.createGroup(name, creator)
    }

    /** Adds [peerID] to the group, rotating the key even though this is an
     * add (matching bitchat-win: every roster change gets a fresh key). The
     * new member gets an invite-type state; every other already-connected
     * member gets a key-update with the same rotated key and roster. */
    fun inviteToGroup(groupId: ByteArray, peerID: String): String? {
        val manager = groupManager ?: return DISABLED_REASON
        val group = manager.group(groupId) ?: return "no such group"
        if (group.creatorFingerprint != delegate.myFingerprint()) return "only the creator can invite members"
        if (!delegate.hasNoiseSession(peerID)) return "no established Noise session with that peer"

        val peerFingerprint = delegate.getPeerFingerprint(peerID) ?: return "peer identity not yet verified"
        val peerSigningKey = delegate.getPeerSigningPublicKey(peerID) ?: return "peer identity not yet verified"
        if (group.isMember(peerFingerprint)) return "peer is already a member"
        if (group.members.size >= GroupProtocolConstants.MAX_MEMBERS) return "group is full"

        val newMember = GroupMember(peerFingerprint, peerSigningKey, delegate.getPeerNickname(peerID) ?: peerID)
        val newRoster = group.members + newMember
        val rotation = manager.rotateKey(groupId, newRoster) ?: return "failed to rotate group key"
        val (rotated, newKey) = rotation

        val invitePayload = buildSignedState(rotated, newKey) ?: return "failed to sign group state"
        sendState(invitePayload, NoisePayloadType.GROUP_INVITE, peerID)
        distributeKeyUpdate(invitePayload, excludeFingerprints = setOf(peerFingerprint))
        return null
    }

    /** Removes [peerID], rotating the key so their old copy can no longer
     * decrypt anything. Remaining members get a real key-update; the removed
     * member gets a SEPARATE state carrying an all-zero throwaway key (never
     * the real rotated key) so their own missing-self check fires locally
     * and they drop the group without ever holding the new key. */
    fun removeFromGroup(groupId: ByteArray, peerID: String): String? {
        val manager = groupManager ?: return DISABLED_REASON
        val group = manager.group(groupId) ?: return "no such group"
        if (group.creatorFingerprint != delegate.myFingerprint()) return "only the creator can remove members"

        val removedFingerprint = delegate.getPeerFingerprint(peerID)
        val remaining = group.members.filter { it.fingerprint != removedFingerprint }
        if (remaining.size == group.members.size) return "peer is not a member"

        val rotation = manager.rotateKey(groupId, remaining) ?: return "failed to rotate group key"
        val (rotated, newKey) = rotation
        val keyUpdatePayload = buildSignedState(rotated, newKey) ?: return "failed to sign group state"
        distributeKeyUpdate(keyUpdatePayload, excludeFingerprints = emptySet())

        // Throwaway state for the removed member: same roster (without them)
        // and epoch, but a fake all-zero key, they must never see the real one.
        val throwawayPayload = buildSignedState(rotated, ALL_ZERO_KEY)
        if (throwawayPayload != null) sendState(throwawayPayload, NoisePayloadType.GROUP_KEY_UPDATE, peerID)
        return null
    }

    /** Local-only: drop a group we're a (non-creator) member of. */
    fun leaveGroup(groupId: ByteArray) {
        groupManager?.removeGroup(groupId)
    }

    fun sendGroupMessage(groupId: ByteArray, content: String): String? {
        val manager = groupManager ?: return DISABLED_REASON
        val group = manager.group(groupId) ?: return "no such group"
        val key = manager.key(groupId) ?: return "no such group"

        val messageId = UUID.randomUUID().toString().uppercase()
        val payload = try {
            GroupCrypto.sealMessage(
                content = content,
                messageId = messageId,
                senderNickname = delegate.myNickname(),
                senderSigningKey = delegate.mySigningPublicKey(),
                timestampMs = System.currentTimeMillis(),
                groupId = groupId,
                epoch = group.epoch,
                key = key,
                sign = delegate::signWithIdentityKey
            )
        } catch (e: GroupCryptoError) {
            return "failed to sign group message"
        }

        // Deliberately UNSIGNED at the outer-packet level: authenticity comes
        // from the Ed25519 signature inside the ciphertext instead, which
        // (unlike an outer signature tied to a since-expired announce) stays
        // verifiable indefinitely, see GroupProtocol.kt's file header.
        val packet = BitchatPacket(
            version = 1u,
            type = MessageType.GROUP_MESSAGE.value,
            senderID = hexToRoutingBytes(delegate.myPeerID()),
            recipientID = SpecialRecipients.BROADCAST,
            timestamp = System.currentTimeMillis().toULong(),
            payload = payload,
            signature = null,
            ttl = AppConstants.MESSAGE_TTL_HOPS
        )
        delegate.sendUnsignedBroadcastPacket(packet)
        return null
    }

    /** Called from the public (unaddressed) packet dispatch path for
     * MessageType.GROUP_MESSAGE, mirroring how MessageType.MESSAGE is
     * handled, floods/relays regardless (that's the centralized relay
     * manager's job for every packet type), this only ever *reads* it. */
    fun handleIncomingGroupMessage(packet: BitchatPacket) {
        val manager = groupManager ?: return // groups disabled: never even tries
        val envelope = GroupMessageEnvelope.decode(packet.payload) ?: return
        val group = manager.group(envelope.groupId) ?: return // unknown group: drop (still relays elsewhere)
        if (envelope.epoch != group.epoch) return // epoch must EXACTLY match, no stale/future acceptance
        val key = manager.key(envelope.groupId) ?: return

        val plaintext = try {
            GroupCrypto.openMessage(envelope, key)
        } catch (e: GroupCryptoError) {
            Log.w(TAG, "Dropping group message for ${group.name}: ${e.message}")
            return
        }

        if (plaintext.senderSigningKey.contentEquals(delegate.mySigningPublicKey())) return // reject own echo
        val member = group.memberWithSigningKey(plaintext.senderSigningKey) ?: return // sender must be in roster

        delegate.onGroupMessageReceived(group.peerIdHex, group.name, member.nickname.ifEmpty { plaintext.senderNickname }, plaintext.content)
    }

    /** Called from the NOISE_ENCRYPTED payload switch for both
     * NoisePayloadType.GROUP_INVITE and GROUP_KEY_UPDATE (same wire form). */
    fun handleIncomingGroupState(data: ByteArray, senderPeerID: String) {
        val manager = groupManager ?: return
        val state = GroupStatePayload.decode(data) ?: return

        // The Noise-session-authenticated peer must independently BE the
        // creator, a member can't forge state even with a valid roster blob.
        val authenticatedSenderFingerprint = delegate.getPeerFingerprint(senderPeerID)
        if (authenticatedSenderFingerprint == null || authenticatedSenderFingerprint != state.creatorFingerprint) {
            Log.w(TAG, "Dropping group state: sender is not the authenticated creator")
            return
        }
        if (!state.verifyCreatorSignature()) {
            Log.w(TAG, "Dropping group state: invalid creator signature")
            return
        }

        val existing = manager.group(state.groupId)
        if (existing != null && state.epoch < existing.epoch) return // never regress epoch

        val myFingerprint = delegate.myFingerprint()
        if (!state.members.any { it.fingerprint == myFingerprint }) {
            // We were removed (or this state never included us): drop it locally.
            if (existing != null) {
                manager.removeGroup(state.groupId)
                delegate.onGroupNotice(existing.peerIdHex, existing.name, "removed from ${existing.name}")
            }
            return
        }

        val wasAlreadyMember = existing != null
        manager.upsert(state.asGroup, state.key)
        if (!wasAlreadyMember) {
            delegate.onGroupNotice(state.asGroup.peerIdHex, state.name, "added to ${state.name}")
        }
    }

    private fun buildSignedState(group: BitchatGroup, key: ByteArray): GroupStatePayload? =
        GroupStatePayload.makeSigned(group, key, delegate::signWithIdentityKey)

    private fun sendState(state: GroupStatePayload, type: NoisePayloadType, peerID: String) {
        val encoded = state.encode() ?: return
        val noisePayload = NoisePayload(type, encoded)
        val encrypted = delegate.encryptForPeer(noisePayload.encode(), peerID) ?: run {
            Log.w(TAG, "Failed to encrypt group state for $peerID")
            return
        }
        val packet = BitchatPacket(
            version = 1u,
            type = MessageType.NOISE_ENCRYPTED.value,
            senderID = hexToRoutingBytes(delegate.myPeerID()),
            recipientID = hexToRoutingBytes(peerID),
            timestamp = System.currentTimeMillis().toULong(),
            payload = encrypted,
            signature = null,
            ttl = AppConstants.MESSAGE_TTL_HOPS
        )
        delegate.sendPrivatePacket(packet)
    }

    private fun distributeKeyUpdate(state: GroupStatePayload, excludeFingerprints: Set<String>) {
        for (member in state.members) {
            if (member.fingerprint == delegate.myFingerprint()) continue // don't send to ourselves
            if (member.fingerprint in excludeFingerprints) continue
            val peerID = delegate.getPeerIDForFingerprint(member.fingerprint) ?: continue // not currently connected
            if (!delegate.hasNoiseSession(peerID)) continue
            sendState(state, NoisePayloadType.GROUP_KEY_UPDATE, peerID)
        }
    }

    private fun hexToRoutingBytes(peerIdHex: String): ByteArray {
        val result = ByteArray(8)
        var temp = peerIdHex
        var index = 0
        while (temp.length >= 2 && index < 8) {
            result[index] = temp.substring(0, 2).toIntOrNull(16)?.toByte() ?: 0
            temp = temp.substring(2)
            index++
        }
        return result
    }
}

interface GroupCoordinatorDelegate {
    fun myPeerID(): String
    fun myNickname(): String
    fun myFingerprint(): String
    fun mySigningPublicKey(): ByteArray
    /** Signs [data] with the local Ed25519 identity key and returns the
     * 64-byte signature, or null on failure, kept as a callback (backed by
     * EncryptionService.signData) rather than exposing the raw private key. */
    fun signWithIdentityKey(data: ByteArray): ByteArray?

    fun getPeerNickname(peerID: String): String?
    fun getPeerFingerprint(peerID: String): String?
    fun getPeerSigningPublicKey(peerID: String): ByteArray?
    fun getPeerIDForFingerprint(fingerprint: String): String?
    fun hasNoiseSession(peerID: String): Boolean
    fun encryptForPeer(data: ByteArray, peerID: String): ByteArray?

    /** Signed, targeted NOISE_ENCRYPTED send, invites/key-updates go through
     * the normal signing path, unlike the group message broadcast below. */
    fun sendPrivatePacket(packet: BitchatPacket)
    /** Deliberately bypasses outer-packet signing, see sendGroupMessage. */
    fun sendUnsignedBroadcastPacket(packet: BitchatPacket)

    fun onGroupMessageReceived(groupPeerId: String, groupName: String, senderNickname: String, content: String)
    fun onGroupNotice(groupPeerId: String, groupName: String, notice: String)
}
