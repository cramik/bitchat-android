package com.bitchat.android.groups

import com.bitchat.android.model.NoisePayload
import com.bitchat.android.protocol.BitchatPacket
import com.bitchat.android.protocol.MessageType
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.SecureRandom

/**
 * End-to-end orchestration test for [GroupCoordinator], two fake "parties"
 * wired directly together (no real BLE/Noise), the same shape as
 * bitchat-win's test_groups_mesh.py (`make_engine`/`link`/`establish`). Real
 * encryption is stubbed as an identity passthrough since GroupCoordinator
 * itself doesn't perform crypto beyond the group protocol, SecurityManager
 * owns that in production and is exercised by its own tests.
 */
private class FakeParty(val peerID: String, val nickname: String, groupsFile: File) {
    val noisePriv: Ed25519PrivateKeyParameters
    val noisePub: Ed25519PublicKeyParameters
    val fingerprint: String = peerID.padStart(64, '0')

    val receivedMessages = mutableListOf<Quadruple>()
    val notices = mutableListOf<Pair<String, String>>()

    private val peerFingerprints = mutableMapOf<String, String>() // peerID -> fingerprint
    private val peerSigningKeys = mutableMapOf<String, ByteArray>() // peerID -> signing pubkey
    private val fingerprintToPeerID = mutableMapOf<String, String>()
    private val sessions = mutableSetOf<String>()
    var partner: FakeParty? = null

    val manager = GroupManager(groupsFile)
    lateinit var coordinator: GroupCoordinator

    data class Quadruple(val groupPeerId: String, val groupName: String, val sender: String, val content: String)

    init {
        val generator = Ed25519KeyPairGenerator()
        generator.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val keyPair = generator.generateKeyPair()
        noisePriv = keyPair.private as Ed25519PrivateKeyParameters
        noisePub = keyPair.public as Ed25519PublicKeyParameters

        coordinator = GroupCoordinator(manager, object : GroupCoordinatorDelegate {
            override fun myPeerID() = peerID
            override fun myNickname() = nickname
            override fun myFingerprint() = fingerprint
            override fun mySigningPublicKey() = noisePub.encoded
            override fun signWithIdentityKey(data: ByteArray) = signEd25519(noisePriv, data)

            override fun getPeerNickname(peerID: String) = if (peerID == partner?.peerID) partner?.nickname else null
            override fun getPeerFingerprint(peerID: String) = peerFingerprints[peerID]
            override fun getPeerSigningPublicKey(peerID: String) = peerSigningKeys[peerID]
            override fun getPeerIDForFingerprint(fingerprint: String) = fingerprintToPeerID[fingerprint]
            override fun hasNoiseSession(peerID: String) = sessions.contains(peerID)
            override fun encryptForPeer(data: ByteArray, peerID: String) = data // identity passthrough

            override fun sendPrivatePacket(packet: BitchatPacket) {
                val target = partner ?: return
                val noisePayload = NoisePayload.decode(packet.payload) ?: return
                target.coordinator.handleIncomingGroupState(noisePayload.data, peerID)
            }

            override fun sendUnsignedBroadcastPacket(packet: BitchatPacket) {
                partner?.coordinator?.handleIncomingGroupMessage(packet)
            }

            override fun onGroupMessageReceived(groupPeerId: String, groupName: String, senderNickname: String, content: String) {
                receivedMessages.add(Quadruple(groupPeerId, groupName, senderNickname, content))
            }

            override fun onGroupNotice(groupPeerId: String, groupName: String, notice: String) {
                notices.add(groupPeerId to notice)
            }
        })
    }

    fun connectTo(other: FakeParty) {
        partner = other
        peerFingerprints[other.peerID] = other.fingerprint
        peerSigningKeys[other.peerID] = other.noisePub.encoded
        fingerprintToPeerID[other.fingerprint] = other.peerID
        sessions.add(other.peerID)
    }
}

class GroupCoordinatorTest {

    private fun tempPath(name: String): File {
        val file = File.createTempFile(name, ".json")
        file.deleteOnExit()
        file.delete()
        return file
    }

    private fun linkedParties(): Pair<FakeParty, FakeParty> {
        val alice = FakeParty("aaaaaaaaaaaaaaaa", "alice", tempPath("alice-groups"))
        val bob = FakeParty("bbbbbbbbbbbbbbbb", "bob", tempPath("bob-groups"))
        alice.connectTo(bob)
        bob.connectTo(alice)
        return alice to bob
    }

    @Test
    fun `full lifecycle, create invite message remove`() {
        val (alice, bob) = linkedParties()

        val group = alice.coordinator.createGroup("my group")!!
        assertEquals(1, group.epoch)

        val inviteReason = alice.coordinator.inviteToGroup(group.groupId, bob.peerID)
        assertNull(inviteReason)

        // Bob got a real invite: notice fired, and he's now a member locally
        // with the rotated epoch (invite always rotates, even for adds).
        assertEquals(1, bob.notices.size)
        assertTrue(bob.notices[0].second.contains("added to my group"))
        val bobGroup = bob.manager.group(group.groupId)!!
        assertEquals(2, bobGroup.epoch)
        assertEquals(2, bobGroup.members.size)

        val aliceGroup = alice.manager.group(group.groupId)!!
        assertEquals(2, aliceGroup.epoch)

        val sendReason = alice.coordinator.sendGroupMessage(group.groupId, "hello group")
        assertNull(sendReason)
        assertEquals(1, bob.receivedMessages.size)
        val received = bob.receivedMessages[0]
        assertEquals(group.peerIdHex, received.groupPeerId)
        assertEquals("my group", received.groupName)
        assertEquals("alice", received.sender)
        assertEquals("hello group", received.content)

        val removeReason = alice.coordinator.removeFromGroup(group.groupId, bob.peerID)
        assertNull(removeReason)
        assertNull(bob.manager.group(group.groupId)) // bob dropped it locally
        assertTrue(bob.notices.any { it.second.contains("removed from") })
        assertEquals(3, alice.manager.group(group.groupId)!!.epoch)
    }

    @Test
    fun `only the creator can invite`() {
        val (alice, bob) = linkedParties()
        val group = alice.coordinator.createGroup("g")!!
        alice.coordinator.inviteToGroup(group.groupId, bob.peerID)

        // Bob is now a member but not the creator.
        val reason = bob.coordinator.inviteToGroup(group.groupId, "cccccccccccccccc")
        assertNotNull(reason)
        assertTrue(reason!!.lowercase().contains("creator"))
    }

    @Test
    fun `only the creator can remove`() {
        val (alice, bob) = linkedParties()
        val group = alice.coordinator.createGroup("g")!!
        alice.coordinator.inviteToGroup(group.groupId, bob.peerID)

        val reason = bob.coordinator.removeFromGroup(group.groupId, alice.peerID)
        assertNotNull(reason)
        assertTrue(reason!!.lowercase().contains("creator"))
    }

    @Test
    fun `cannot invite without an established session`() {
        val alice = FakeParty("aaaaaaaaaaaaaaaa", "alice", tempPath("alice-groups2"))
        val bob = FakeParty("bbbbbbbbbbbbbbbb", "bob", tempPath("bob-groups2"))
        // Deliberately not connected, no session, no known fingerprint.

        val group = alice.coordinator.createGroup("g")!!
        val reason = alice.coordinator.inviteToGroup(group.groupId, bob.peerID)
        assertNotNull(reason)
        assertTrue(reason!!.lowercase().contains("session"))
    }

    @Test
    fun `groups disabled is a safe no-op`() {
        val coordinator = GroupCoordinator(null, object : GroupCoordinatorDelegate {
            override fun myPeerID() = "0000000000000000"
            override fun myNickname() = "solo"
            override fun myFingerprint() = "0".repeat(64)
            override fun mySigningPublicKey() = ByteArray(32)
            override fun signWithIdentityKey(data: ByteArray) = ByteArray(64)
            override fun getPeerNickname(peerID: String): String? = null
            override fun getPeerFingerprint(peerID: String): String? = null
            override fun getPeerSigningPublicKey(peerID: String): ByteArray? = null
            override fun getPeerIDForFingerprint(fingerprint: String): String? = null
            override fun hasNoiseSession(peerID: String) = false
            override fun encryptForPeer(data: ByteArray, peerID: String): ByteArray? = null
            override fun sendPrivatePacket(packet: BitchatPacket) {}
            override fun sendUnsignedBroadcastPacket(packet: BitchatPacket) {}
            override fun onGroupMessageReceived(groupPeerId: String, groupName: String, senderNickname: String, content: String) {}
            override fun onGroupNotice(groupPeerId: String, groupName: String, notice: String) {}
        })

        assertNull(coordinator.createGroup("g"))
        assertEquals("groups are disabled", coordinator.sendGroupMessage(ByteArray(16), "hi"))
        assertEquals("groups are disabled", coordinator.inviteToGroup(ByteArray(16), "someone"))
        assertTrue(coordinator.listGroups().isEmpty())
    }
}
