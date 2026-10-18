package com.bitchat.android.groups

import com.google.crypto.tink.subtle.ChaCha20Poly1305
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Creator-managed E2EE private groups: wire formats and crypto.
 *
 * Ported byte-exact from bitchat-reference (iOS)'s
 * `Services/Groups/GroupProtocol.swift`, via the already-verified Python
 * port at bitchat-win's `bitchat/groups.py`, this feature does not exist
 * in stock bitchat-android at all (no GROUP_MESSAGE MessageType, no
 * GroupStore), so there is no second on-platform reference to diff against.
 *
 * Design in one paragraph: a group is a random 16-byte ID plus a 32-byte
 * ChaCha20-Poly1305 symmetric key, both known only to members. The creator
 * signs (Ed25519) every roster/key change ("group state") and distributes it
 * 1:1 over each member's existing Noise session; a state's signature is
 * verified against the *creator's* signing key as pinned inside the roster
 * itself, and the Noise session peer must independently authenticate as that
 * same creator fingerprint. Every roster change (add OR remove) bumps the
 * epoch and gets a fresh key. Chat messages are ChaCha20-Poly1305-sealed
 * with the current epoch key and broadcast like a public message
 * (MessageType.GROUP_MESSAGE, 0x25), but that outer packet is deliberately
 * UNSIGNED: authenticity comes from the Ed25519 signature *inside* the
 * ciphertext, verified against the sender's roster-pinned signing key, which
 * stays verifiable indefinitely (unlike an outer signature tied to a
 * since-expired announce), so a store-and-forward copy delivered long after
 * the fact still checks out.
 */
object GroupProtocolConstants {
    const val MAX_MEMBERS = 16
    const val GROUP_ID_LENGTH = 16
    const val KEY_LENGTH = 32
    const val FINGERPRINT_LENGTH = 32 // SHA-256 fingerprint, raw bytes (64 hex chars)
    const val SIGNING_KEY_LENGTH = 32 // Ed25519 public key
    const val MAX_NICKNAME_BYTES = 64
    const val NONCE_LENGTH = 12 // standard ChaCha20-Poly1305, not XChaCha

    val SIGNING_DOMAIN = "bitchat-group-v1".toByteArray(Charsets.UTF_8)
    val MESSAGE_SIGNING_DOMAIN = "bitchat-group-msg-v1".toByteArray(Charsets.UTF_8)

    const val GROUP_PEER_ID_PREFIX = "group_"
}

class GroupTLVError(message: String) : Exception(message)
class GroupCryptoError(message: String, cause: Throwable? = null) : Exception(message, cause)

private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun hexToBytes(hex: String): ByteArray? {
    if (hex.length % 2 != 0) return null
    val out = ByteArray(hex.length / 2)
    for (i in out.indices) {
        val hi = Character.digit(hex[i * 2], 16)
        val lo = Character.digit(hex[i * 2 + 1], 16)
        if (hi < 0 || lo < 0) return null // Character.digit returns -1 (not an exception) on invalid hex
        out[i] = ((hi shl 4) + lo).toByte()
    }
    return out
}

private fun tlvPut(out: java.io.ByteArrayOutputStream, fieldType: Int, value: ByteArray) {
    if (value.size > 0xFFFF) throw GroupTLVError("value too long for a 16-bit TLV length field: ${value.size} bytes")
    out.write(fieldType)
    out.write((value.size ushr 8) and 0xFF)
    out.write(value.size and 0xFF)
    out.write(value)
}

private data class TlvField(val type: Int, val value: ByteArray)

private fun tlvParse(data: ByteArray): List<TlvField>? {
    val fields = mutableListOf<TlvField>()
    var offset = 0
    while (offset < data.size) {
        if (data.size - offset < 3) return null
        val fieldType = data[offset].toInt() and 0xFF
        val length = ((data[offset + 1].toInt() and 0xFF) shl 8) or (data[offset + 2].toInt() and 0xFF)
        offset += 3
        if (data.size - offset < length) return null
        fields.add(TlvField(fieldType, data.copyOfRange(offset, offset + length)))
        offset += length
    }
    return fields
}

/** UTF-8 bytes of [nickname], trimmed to at most MAX_NICKNAME_BYTES, dropping
 * whole characters so the result is never split mid-codepoint. */
private fun truncateNickname(nickname: String): ByteArray {
    var candidate = nickname
    while (candidate.toByteArray(Charsets.UTF_8).size > GroupProtocolConstants.MAX_NICKNAME_BYTES) {
        candidate = candidate.substring(0, candidate.length - 1)
    }
    return candidate.toByteArray(Charsets.UTF_8)
}

data class GroupMember(
    val fingerprint: String, // 64 hex chars (32-byte SHA-256 fingerprint)
    val signingKey: ByteArray, // 32-byte Ed25519 public key
    val nickname: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is GroupMember) return false
        return fingerprint == other.fingerprint && signingKey.contentEquals(other.signingKey) && nickname == other.nickname
    }
    override fun hashCode(): Int = fingerprint.hashCode() * 31 + signingKey.contentHashCode()
}

data class BitchatGroup(
    val groupId: ByteArray, // 16 random bytes
    val name: String,
    val epoch: Int, // bumps on every key rotation
    val members: List<GroupMember>,
    val creatorFingerprint: String // 64 hex chars; the only identity allowed to sign state
) {
    /** Virtual conversation ID, matches PeerID(groupID:), used to key this
     * group's chat the same way a 1:1 DM's peerIDHex does. */
    val peerIdHex: String get() = GroupProtocolConstants.GROUP_PEER_ID_PREFIX + groupId.toHex()

    val creator: GroupMember? get() = members.firstOrNull { it.fingerprint == creatorFingerprint }

    fun isMember(fingerprint: String): Boolean = members.any { it.fingerprint == fingerprint }

    fun memberWithSigningKey(signingKey: ByteArray): GroupMember? =
        members.firstOrNull { it.signingKey.contentEquals(signingKey) }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BitchatGroup) return false
        return groupId.contentEquals(other.groupId) && name == other.name && epoch == other.epoch &&
            members == other.members && creatorFingerprint == other.creatorFingerprint
    }
    override fun hashCode(): Int = groupId.contentHashCode()
}

/** Deterministic roster blob: count byte, then per member the raw 32-byte
 * fingerprint, 32-byte signing key, and length-prefixed UTF-8 nickname. The
 * creator signature covers the SHA-256 of these exact bytes, so this
 * encoding must be reproduced identically to verify. */
object GroupRosterCoding {
    fun encode(members: List<GroupMember>): ByteArray? {
        if (members.size > GroupProtocolConstants.MAX_MEMBERS) return null
        val out = java.io.ByteArrayOutputStream()
        out.write(members.size)
        for (member in members) {
            val fingerprintBytes = hexToBytes(member.fingerprint) ?: return null
            if (fingerprintBytes.size != GroupProtocolConstants.FINGERPRINT_LENGTH ||
                member.signingKey.size != GroupProtocolConstants.SIGNING_KEY_LENGTH
            ) return null
            out.write(fingerprintBytes)
            out.write(member.signingKey)
            val nicknameBytes = truncateNickname(member.nickname)
            out.write(nicknameBytes.size)
            out.write(nicknameBytes)
        }
        return out.toByteArray()
    }

    fun decode(data: ByteArray): List<GroupMember>? {
        if (data.isEmpty() || (data[0].toInt() and 0xFF) > GroupProtocolConstants.MAX_MEMBERS) return null
        val count = data[0].toInt() and 0xFF
        val members = mutableListOf<GroupMember>()
        var offset = 1
        repeat(count) {
            val fixed = GroupProtocolConstants.FINGERPRINT_LENGTH + GroupProtocolConstants.SIGNING_KEY_LENGTH + 1
            if (data.size - offset < fixed) return null
            val fingerprint = data.copyOfRange(offset, offset + GroupProtocolConstants.FINGERPRINT_LENGTH).toHex()
            offset += GroupProtocolConstants.FINGERPRINT_LENGTH
            val signingKey = data.copyOfRange(offset, offset + GroupProtocolConstants.SIGNING_KEY_LENGTH)
            offset += GroupProtocolConstants.SIGNING_KEY_LENGTH
            val nickLength = data[offset].toInt() and 0xFF
            offset += 1
            if (data.size - offset < nickLength) return null
            val nickname = try {
                String(data, offset, nickLength, Charsets.UTF_8)
            } catch (e: Exception) {
                return null
            }
            offset += nickLength
            members.add(GroupMember(fingerprint, signingKey, nickname))
        }
        if (offset != data.size) return null
        return members
    }
}

/** Creator-signed group state, the same wire form serves invites
 * (NoisePayloadType 0x06) and key updates (0x07), sent as the payload of an
 * ordinary NOISE_ENCRYPTED packet through an already-established Noise
 * session, same as a private text message. Receivers verify the creator
 * signature against the creator's signing key pinned in the roster, and
 * separately require the authenticated Noise session peer to BE that same
 * creator. */
data class GroupStatePayload(
    val groupId: ByteArray,
    val name: String,
    val key: ByteArray, // 32-byte ChaCha20-Poly1305 group key for `epoch`
    val epoch: Int,
    val members: List<GroupMember>,
    val creatorFingerprint: String,
    val signature: ByteArray // 64-byte Ed25519 signature by the creator
) {
    val asGroup: BitchatGroup
        get() = BitchatGroup(groupId, name, epoch, members, creatorFingerprint)

    fun encode(): ByteArray? {
        val rosterBlob = GroupRosterCoding.encode(members) ?: return null
        val fingerprintBytes = hexToBytes(creatorFingerprint) ?: return null
        if (fingerprintBytes.size != GroupProtocolConstants.FINGERPRINT_LENGTH) return null
        val out = java.io.ByteArrayOutputStream()
        return try {
            tlvPut(out, FIELD_GROUP_ID, groupId)
            tlvPut(out, FIELD_NAME, name.toByteArray(Charsets.UTF_8))
            tlvPut(out, FIELD_KEY, key)
            tlvPut(out, FIELD_EPOCH, epochBytes(epoch))
            tlvPut(out, FIELD_ROSTER, rosterBlob)
            tlvPut(out, FIELD_CREATOR_FINGERPRINT, fingerprintBytes)
            tlvPut(out, FIELD_SIGNATURE, signature)
            out.toByteArray()
        } catch (e: GroupTLVError) {
            null
        }
    }

    fun verifyCreatorSignature(): Boolean {
        if (members.size > GroupProtocolConstants.MAX_MEMBERS) return false
        val creator = members.firstOrNull { it.fingerprint == creatorFingerprint } ?: return false
        val rosterBlob = GroupRosterCoding.encode(members) ?: return false
        val content = signingContent(groupId, epoch, key, rosterBlob, name)
        return verifyEd25519(creator.signingKey, content, signature)
    }

    companion object {
        private const val FIELD_GROUP_ID = 0x01
        private const val FIELD_NAME = 0x02
        private const val FIELD_KEY = 0x03
        private const val FIELD_EPOCH = 0x04
        private const val FIELD_ROSTER = 0x05
        private const val FIELD_CREATOR_FINGERPRINT = 0x06
        private const val FIELD_SIGNATURE = 0x07

        private fun epochBytes(epoch: Int): ByteArray = byteArrayOf(
            ((epoch ushr 24) and 0xFF).toByte(),
            ((epoch ushr 16) and 0xFF).toByte(),
            ((epoch ushr 8) and 0xFF).toByte(),
            (epoch and 0xFF).toByte()
        )

        private fun epochFromBytes(value: ByteArray): Int =
            ((value[0].toInt() and 0xFF) shl 24) or ((value[1].toInt() and 0xFF) shl 16) or
                ((value[2].toInt() and 0xFF) shl 8) or (value[3].toInt() and 0xFF)

        fun signingContent(groupId: ByteArray, epoch: Int, key: ByteArray, rosterBlob: ByteArray, name: String): ByteArray {
            val out = java.io.ByteArrayOutputStream()
            out.write(GroupProtocolConstants.SIGNING_DOMAIN)
            out.write(groupId)
            out.write(epochBytes(epoch))
            out.write(sha256(key))
            out.write(sha256(rosterBlob))
            out.write(sha256(name.toByteArray(Charsets.UTF_8)))
            return out.toByteArray()
        }

        /** [sign] receives the exact bytes to sign and returns a 64-byte
         * Ed25519 signature, kept as a callback rather than a raw private
         * key parameter so callers (e.g. EncryptionService.signData) never
         * have to hand the key itself out of its owning boundary. */
        fun makeSigned(group: BitchatGroup, key: ByteArray, sign: (ByteArray) -> ByteArray?): GroupStatePayload? {
            val rosterBlob = GroupRosterCoding.encode(group.members) ?: return null
            val content = signingContent(group.groupId, group.epoch, key, rosterBlob, group.name)
            val signature = sign(content) ?: return null
            return GroupStatePayload(
                groupId = group.groupId,
                name = group.name,
                key = key,
                epoch = group.epoch,
                members = group.members,
                creatorFingerprint = group.creatorFingerprint,
                signature = signature
            )
        }

        fun decode(data: ByteArray): GroupStatePayload? {
            val fields = tlvParse(data) ?: return null
            var groupId: ByteArray? = null
            var name: String? = null
            var key: ByteArray? = null
            var epoch: Int? = null
            var members: List<GroupMember>? = null
            var creatorFingerprint: String? = null
            var signature: ByteArray? = null

            for (field in fields) {
                when (field.type) {
                    FIELD_GROUP_ID -> if (field.value.size == GroupProtocolConstants.GROUP_ID_LENGTH) groupId = field.value
                    FIELD_NAME -> name = try { String(field.value, Charsets.UTF_8) } catch (e: Exception) { null }
                    FIELD_KEY -> if (field.value.size == GroupProtocolConstants.KEY_LENGTH) key = field.value
                    FIELD_EPOCH -> if (field.value.size == 4) epoch = epochFromBytes(field.value)
                    FIELD_ROSTER -> members = GroupRosterCoding.decode(field.value)
                    FIELD_CREATOR_FINGERPRINT -> if (field.value.size == GroupProtocolConstants.FINGERPRINT_LENGTH) creatorFingerprint = field.value.toHex()
                    FIELD_SIGNATURE -> if (field.value.size == 64) signature = field.value
                    // else: unknown TLV type, forward compatible, ignore
                }
            }

            if (groupId == null || name == null || key == null || epoch == null || members == null ||
                creatorFingerprint == null || signature == null
            ) return null
            return GroupStatePayload(groupId, name, key, epoch, members, creatorFingerprint, signature)
        }
    }
}

/** Cleartext framing of a group message broadcast (the payload of a
 * MessageType.GROUP_MESSAGE / 0x25 packet). Only the group ID, epoch, and
 * nonce are visible to relays; everything else, sender, content,
 * timestamp, is inside the ChaCha20-Poly1305 ciphertext. */
data class GroupMessageEnvelope(
    val groupId: ByteArray,
    val epoch: Int,
    val nonce: ByteArray,
    val ciphertext: ByteArray // ChaCha20-Poly1305 ciphertext || 16-byte tag
) {
    fun encode(): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        tlvPut(out, FIELD_GROUP_ID, groupId)
        tlvPut(out, FIELD_EPOCH, epochBytes(epoch))
        tlvPut(out, FIELD_NONCE, nonce)
        tlvPut(out, FIELD_CIPHERTEXT, ciphertext)
        return out.toByteArray()
    }

    companion object {
        private const val FIELD_GROUP_ID = 0x01
        private const val FIELD_EPOCH = 0x02
        private const val FIELD_NONCE = 0x03
        private const val FIELD_CIPHERTEXT = 0x04

        private fun epochBytes(epoch: Int): ByteArray = byteArrayOf(
            ((epoch ushr 24) and 0xFF).toByte(),
            ((epoch ushr 16) and 0xFF).toByte(),
            ((epoch ushr 8) and 0xFF).toByte(),
            (epoch and 0xFF).toByte()
        )

        private fun epochFromBytes(value: ByteArray): Int =
            ((value[0].toInt() and 0xFF) shl 24) or ((value[1].toInt() and 0xFF) shl 16) or
                ((value[2].toInt() and 0xFF) shl 8) or (value[3].toInt() and 0xFF)

        fun decode(data: ByteArray): GroupMessageEnvelope? {
            val fields = tlvParse(data) ?: return null
            var groupId: ByteArray? = null
            var epoch: Int? = null
            var nonce: ByteArray? = null
            var ciphertext: ByteArray? = null
            for (field in fields) {
                when (field.type) {
                    FIELD_GROUP_ID -> if (field.value.size == GroupProtocolConstants.GROUP_ID_LENGTH) groupId = field.value
                    FIELD_EPOCH -> if (field.value.size == 4) epoch = epochFromBytes(field.value)
                    FIELD_NONCE -> if (field.value.size == GroupProtocolConstants.NONCE_LENGTH) nonce = field.value
                    FIELD_CIPHERTEXT -> if (field.value.isNotEmpty()) ciphertext = field.value
                }
            }
            if (groupId == null || epoch == null || nonce == null || ciphertext == null) return null
            return GroupMessageEnvelope(groupId, epoch, nonce, ciphertext)
        }
    }
}

data class GroupMessagePlaintext(
    val messageId: String,
    val senderSigningKey: ByteArray,
    val senderNickname: String,
    val timestampMs: Long,
    val content: String
)

/** Group message sealing/opening and Ed25519 sign/verify helpers. BouncyCastle
 * is used for Ed25519 (matching EncryptionService.kt's existing convention);
 * Tink's [ChaCha20Poly1305] is used for the AEAD (matching NostrCrypto.kt's
 * existing convention for XChaCha20Poly1305), its `encrypt`/`decrypt`
 * return/expect `nonce || ciphertext || tag` concatenated, so the wire's
 * separate nonce/ciphertext TLV fields are just a split/rejoin of that. */
object GroupCrypto {

    private val secureRandom = SecureRandom()

    fun randomBytes(length: Int): ByteArray {
        val out = ByteArray(length)
        secureRandom.nextBytes(out)
        return out
    }

    fun messageSigningContent(groupId: ByteArray, epoch: Int, messageId: String, timestampMs: Long, content: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(GroupProtocolConstants.MESSAGE_SIGNING_DOMAIN)
        out.write(groupId)
        out.write(byteArrayOf(((epoch ushr 24) and 0xFF).toByte(), ((epoch ushr 16) and 0xFF).toByte(), ((epoch ushr 8) and 0xFF).toByte(), (epoch and 0xFF).toByte()))
        out.write(messageId.toByteArray(Charsets.UTF_8))
        out.write(longToBytes(timestampMs))
        out.write(content.toByteArray(Charsets.UTF_8))
        return out.toByteArray()
    }

    private fun longToBytes(value: Long): ByteArray {
        val out = ByteArray(8)
        for (i in 0 until 8) {
            out[7 - i] = ((value ushr (8 * i)) and 0xFF).toByte()
        }
        return out
    }

    private fun bytesToLong(data: ByteArray): Long {
        var result = 0L
        for (b in data) {
            result = (result shl 8) or (b.toLong() and 0xFF)
        }
        return result
    }

    /** Seals a group message: builds the signed inner TLV and encrypts it
     * with the epoch key. The cleartext group ID and epoch are bound into
     * the AEAD as associated data so ciphertext cannot be replayed across
     * groups or epochs. Returns the encoded 0x25 packet payload (a
     * GroupMessageEnvelope). */
    fun sealMessage(
        content: String,
        messageId: String,
        senderNickname: String,
        senderSigningKey: ByteArray,
        timestampMs: Long,
        groupId: ByteArray,
        epoch: Int,
        key: ByteArray,
        sign: (ByteArray) -> ByteArray?
    ): ByteArray {
        val signingContent = messageSigningContent(groupId, epoch, messageId, timestampMs, content)
        val signature = sign(signingContent) ?: throw GroupCryptoError("failed to sign group message")

        val inner = java.io.ByteArrayOutputStream()
        tlvPut(inner, 0x01, messageId.toByteArray(Charsets.UTF_8))
        tlvPut(inner, 0x02, senderSigningKey)
        tlvPut(inner, 0x03, senderNickname.toByteArray(Charsets.UTF_8))
        tlvPut(inner, 0x04, longToBytes(timestampMs))
        tlvPut(inner, 0x05, content.toByteArray(Charsets.UTF_8))
        tlvPut(inner, 0x06, signature)

        val aad = groupId + byteArrayOf(((epoch ushr 24) and 0xFF).toByte(), ((epoch ushr 16) and 0xFF).toByte(), ((epoch ushr 8) and 0xFF).toByte(), (epoch and 0xFF).toByte())
        val aead = ChaCha20Poly1305(key)
        val combined = aead.encrypt(inner.toByteArray(), aad) // nonce || ciphertext || tag
        val nonce = combined.copyOfRange(0, GroupProtocolConstants.NONCE_LENGTH)
        val ciphertext = combined.copyOfRange(GroupProtocolConstants.NONCE_LENGTH, combined.size)

        val envelope = GroupMessageEnvelope(groupId, epoch, nonce, ciphertext)
        return envelope.encode()
    }

    /** Opens a group message envelope with the epoch key: decrypts, parses
     * the inner TLV, and verifies the sender's Ed25519 signature. Roster
     * membership of the sender is the CALLER's check, this function only
     * proves the payload was authored by whoever holds `senderSigningKey`. */
    fun openMessage(envelope: GroupMessageEnvelope, key: ByteArray): GroupMessagePlaintext {
        val aad = envelope.groupId + byteArrayOf(
            ((envelope.epoch ushr 24) and 0xFF).toByte(), ((envelope.epoch ushr 16) and 0xFF).toByte(),
            ((envelope.epoch ushr 8) and 0xFF).toByte(), (envelope.epoch and 0xFF).toByte()
        )
        val combined = envelope.nonce + envelope.ciphertext
        val inner = try {
            ChaCha20Poly1305(key).decrypt(combined, aad)
        } catch (e: Exception) {
            throw GroupCryptoError("decryption failed", e)
        }

        val fields = tlvParse(inner) ?: throw GroupCryptoError("malformed inner payload")
        var messageId: String? = null
        var senderSigningKey: ByteArray? = null
        var senderNickname: String? = null
        var timestampMs: Long? = null
        var content: String? = null
        var signature: ByteArray? = null

        for (field in fields) {
            when (field.type) {
                0x01 -> messageId = try { String(field.value, Charsets.UTF_8) } catch (e: Exception) { null }
                0x02 -> if (field.value.size == GroupProtocolConstants.SIGNING_KEY_LENGTH) senderSigningKey = field.value
                0x03 -> senderNickname = try { String(field.value, Charsets.UTF_8) } catch (e: Exception) { null }
                0x04 -> if (field.value.size == 8) timestampMs = bytesToLong(field.value)
                0x05 -> content = try { String(field.value, Charsets.UTF_8) } catch (e: Exception) { null }
                0x06 -> if (field.value.size == 64) signature = field.value
            }
        }

        if (messageId == null || senderSigningKey == null || senderNickname == null ||
            timestampMs == null || content == null || signature == null
        ) throw GroupCryptoError("malformed inner payload")

        val signingContent = messageSigningContent(envelope.groupId, envelope.epoch, messageId, timestampMs, content)
        if (!verifyEd25519(senderSigningKey, signingContent, signature)) {
            throw GroupCryptoError("bad sender signature")
        }

        return GroupMessagePlaintext(messageId, senderSigningKey, senderNickname, timestampMs, content)
    }
}

fun signEd25519(privateKey: Ed25519PrivateKeyParameters, data: ByteArray): ByteArray {
    val signer = Ed25519Signer()
    signer.init(true, privateKey)
    signer.update(data, 0, data.size)
    return signer.generateSignature()
}

fun verifyEd25519(publicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
    if (publicKey.size != GroupProtocolConstants.SIGNING_KEY_LENGTH) return false
    return try {
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(data, 0, data.size)
        verifier.verifySignature(signature)
    } catch (e: Exception) {
        false
    }
}

fun groupIdFromPeerId(peerIdHex: String): ByteArray? {
    if (!peerIdHex.startsWith(GroupProtocolConstants.GROUP_PEER_ID_PREFIX)) return null
    return hexToBytes(peerIdHex.substring(GroupProtocolConstants.GROUP_PEER_ID_PREFIX.length))
}
