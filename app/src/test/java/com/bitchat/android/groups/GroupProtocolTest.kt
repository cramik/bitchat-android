package com.bitchat.android.groups

import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

private fun generateEd25519(): Pair<Ed25519PrivateKeyParameters, Ed25519PublicKeyParameters> {
    val generator = Ed25519KeyPairGenerator()
    generator.init(Ed25519KeyGenerationParameters(SecureRandom()))
    val keyPair = generator.generateKeyPair()
    return (keyPair.private as Ed25519PrivateKeyParameters) to (keyPair.public as Ed25519PublicKeyParameters)
}

private fun randomBytes(n: Int): ByteArray = ByteArray(n).also { SecureRandom().nextBytes(it) }

private fun fingerprintHex(seed: Byte): String = ByteArray(32) { seed }.joinToString("") { "%02x".format(it) }

class GroupProtocolTest {

    // roster TLV

    @Test
    fun `roster round trips through encode and decode`() {
        val members = listOf(
            GroupMember(fingerprintHex(1), randomBytes(32), "alice"),
            GroupMember(fingerprintHex(2), randomBytes(32), "bob")
        )
        val encoded = GroupRosterCoding.encode(members)
        assertNotNull(encoded)
        val decoded = GroupRosterCoding.decode(encoded!!)
        assertEquals(members, decoded)
    }

    @Test
    fun `roster encode rejects more than max members`() {
        val members = (0 until GroupProtocolConstants.MAX_MEMBERS + 1).map {
            GroupMember(fingerprintHex(it.toByte()), randomBytes(32), "m$it")
        }
        assertNull(GroupRosterCoding.encode(members))
    }

    @Test
    fun `roster truncates nickname on a character boundary`() {
        // A nickname whose UTF-8 encoding is well over the 64-byte cap.
        val longNickname = "x".repeat(200)
        val members = listOf(GroupMember(fingerprintHex(1), randomBytes(32), longNickname))
        val decoded = GroupRosterCoding.decode(GroupRosterCoding.encode(members)!!)!!
        assertTrue(decoded[0].nickname.toByteArray(Charsets.UTF_8).size <= GroupProtocolConstants.MAX_NICKNAME_BYTES)
    }

    // GroupStatePayload

    @Test
    fun `group state round trips and verifies creator signature`() {
        val (creatorPriv, creatorPub) = generateEd25519()
        val creator = GroupMember(fingerprintHex(1), creatorPub.encoded, "alice")
        val group = BitchatGroup(randomBytes(16), "test group", 1, listOf(creator), creator.fingerprint)
        val key = randomBytes(32)

        val state = GroupStatePayload.makeSigned(group, key) { data -> signEd25519(creatorPriv, data) }
        assertNotNull(state)
        assertTrue(state!!.verifyCreatorSignature())

        val decoded = GroupStatePayload.decode(state.encode()!!)
        assertNotNull(decoded)
        assertTrue(decoded!!.verifyCreatorSignature())
        assertArrayEquals(state.groupId, decoded.groupId)
        assertEquals(state.epoch, decoded.epoch)
        assertEquals(state.name, decoded.name)
    }

    @Test
    fun `group state signature rejects a tampered key`() {
        val (creatorPriv, creatorPub) = generateEd25519()
        val creator = GroupMember(fingerprintHex(1), creatorPub.encoded, "alice")
        val group = BitchatGroup(randomBytes(16), "test group", 1, listOf(creator), creator.fingerprint)
        val state = GroupStatePayload.makeSigned(group, randomBytes(32)) { data -> signEd25519(creatorPriv, data) }!!

        val tampered = state.copy(key = randomBytes(32))
        assertFalse(tampered.verifyCreatorSignature())
    }

    @Test
    fun `group state signature rejects a non-creator signer`() {
        val (_, creatorPub) = generateEd25519()
        val (impersonatorPriv, _) = generateEd25519()
        val creator = GroupMember(fingerprintHex(1), creatorPub.encoded, "alice")
        val group = BitchatGroup(randomBytes(16), "test group", 1, listOf(creator), creator.fingerprint)

        // Signed by a key that isn't the pinned creator's, signature must not verify
        // against the roster-pinned creator public key.
        val state = GroupStatePayload.makeSigned(group, randomBytes(32)) { data -> signEd25519(impersonatorPriv, data) }!!
        assertFalse(state.verifyCreatorSignature())
    }

    @Test
    fun `group state rejects unknown creator fingerprint not in roster`() {
        val (creatorPriv, creatorPub) = generateEd25519()
        val creator = GroupMember(fingerprintHex(1), creatorPub.encoded, "alice")
        val group = BitchatGroup(randomBytes(16), "test group", 1, listOf(creator), creator.fingerprint)
        val state = GroupStatePayload.makeSigned(group, randomBytes(32)) { data -> signEd25519(creatorPriv, data) }!!

        val withoutCreator = state.copy(members = listOf(GroupMember(fingerprintHex(9), randomBytes(32), "mallory")))
        assertFalse(withoutCreator.verifyCreatorSignature())
    }

    // group message crypto

    @Test
    fun `seal and open message round trips`() {
        val (senderPriv, senderPub) = generateEd25519()
        val groupId = randomBytes(16)
        val key = randomBytes(32)

        val payload = GroupCrypto.sealMessage(
            content = "hello group",
            messageId = "MSG-1",
            senderNickname = "alice",
            senderSigningKey = senderPub.encoded,
            timestampMs = 1_700_000_000_000L,
            groupId = groupId,
            epoch = 3,
            key = key,
            sign = { data -> signEd25519(senderPriv, data) }
        )

        val envelope = GroupMessageEnvelope.decode(payload)!!
        assertArrayEquals(groupId, envelope.groupId)
        assertEquals(3, envelope.epoch)

        val plaintext = GroupCrypto.openMessage(envelope, key)
        assertEquals("hello group", plaintext.content)
        assertEquals("MSG-1", plaintext.messageId)
        assertEquals("alice", plaintext.senderNickname)
        assertArrayEquals(senderPub.encoded, plaintext.senderSigningKey)
    }

    @Test(expected = GroupCryptoError::class)
    fun `open message rejects wrong key`() {
        val (senderPriv, senderPub) = generateEd25519()
        val groupId = randomBytes(16)
        val payload = GroupCrypto.sealMessage(
            "hi", "MSG-1", "alice", senderPub.encoded, 1L, groupId, 1, randomBytes(32)
        ) { data -> signEd25519(senderPriv, data) }
        val envelope = GroupMessageEnvelope.decode(payload)!!
        GroupCrypto.openMessage(envelope, randomBytes(32)) // wrong key, AEAD tag must not verify
    }

    @Test(expected = GroupCryptoError::class)
    fun `open message rejects epoch not bound into AAD`() {
        val (senderPriv, senderPub) = generateEd25519()
        val groupId = randomBytes(16)
        val key = randomBytes(32)
        val payload = GroupCrypto.sealMessage(
            "hi", "MSG-1", "alice", senderPub.encoded, 1L, groupId, 1, key
        ) { data -> signEd25519(senderPriv, data) }
        val envelope = GroupMessageEnvelope.decode(payload)!!

        // Same key, different epoch than what was sealed, AAD mismatch must
        // fail decryption, proving epoch is bound and can't be replayed across epochs.
        val retargeted = envelope.copy(epoch = 2)
        GroupCrypto.openMessage(retargeted, key)
    }

    @Test(expected = GroupCryptoError::class)
    fun `open message rejects tampered ciphertext`() {
        val (senderPriv, senderPub) = generateEd25519()
        val groupId = randomBytes(16)
        val key = randomBytes(32)
        val payload = GroupCrypto.sealMessage(
            "hi", "MSG-1", "alice", senderPub.encoded, 1L, groupId, 1, key
        ) { data -> signEd25519(senderPriv, data) }
        val envelope = GroupMessageEnvelope.decode(payload)!!

        val tamperedCiphertext = envelope.ciphertext.copyOf()
        tamperedCiphertext[tamperedCiphertext.size / 2] = (tamperedCiphertext[tamperedCiphertext.size / 2] + 1).toByte()
        GroupCrypto.openMessage(envelope.copy(ciphertext = tamperedCiphertext), key)
    }

    @Test
    fun `envelope encode decode round trips`() {
        val envelope = GroupMessageEnvelope(randomBytes(16), 7, randomBytes(GroupProtocolConstants.NONCE_LENGTH), randomBytes(48))
        val decoded = GroupMessageEnvelope.decode(envelope.encode())!!
        assertArrayEquals(envelope.groupId, decoded.groupId)
        assertEquals(envelope.epoch, decoded.epoch)
        assertArrayEquals(envelope.nonce, decoded.nonce)
        assertArrayEquals(envelope.ciphertext, decoded.ciphertext)
    }

    @Test
    fun `groupIdFromPeerId round trips with BitchatGroup peerIdHex`() {
        val group = BitchatGroup(randomBytes(16), "g", 1, listOf(GroupMember(fingerprintHex(1), randomBytes(32), "a")), fingerprintHex(1))
        val recovered = groupIdFromPeerId(group.peerIdHex)
        assertArrayEquals(group.groupId, recovered)
    }

    @Test
    fun `groupIdFromPeerId rejects non-group peer ids`() {
        assertNull(groupIdFromPeerId("deadbeefdeadbeef"))
    }
}
