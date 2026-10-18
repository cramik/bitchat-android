package com.bitchat.android.mesh

import com.bitchat.android.model.BitchatFilePacket

/**
 * Transport-agnostic mesh service API for UI and routing layers.
 */
interface MeshService {
    val myPeerID: String
    var delegate: MeshDelegate?

    fun startServices()
    fun stopServices()

    fun sendMessage(content: String, mentions: List<String> = emptyList(), channel: String? = null)
    fun sendPrivateMessage(content: String, recipientPeerID: String, recipientNickname: String, messageID: String? = null)
    fun sendReadReceipt(messageID: String, recipientPeerID: String, readerNickname: String)
    fun sendDeliveryAck(messageID: String, recipientPeerID: String) {}
    fun sendFavoriteNotification(peerID: String, isFavorite: Boolean) {}
    fun sendVerifyChallenge(peerID: String, noiseKeyHex: String, nonceA: ByteArray)
    fun sendVerifyResponse(peerID: String, noiseKeyHex: String, nonceA: ByteArray)
    fun sendFileBroadcast(file: BitchatFilePacket)
    fun sendFilePrivate(recipientPeerID: String, file: BitchatFilePacket)
    fun sendVoiceFrame(recipientPeerID: String?, payload: ByteArray)
    fun prepareFilePrivate(
        recipientPeerID: String,
        file: BitchatFilePacket,
        transferId: String,
        allowLegacyFallback: Boolean
    ): PrivateMediaPreparation
    fun cancelFileTransfer(transferId: String): Boolean

    fun sendBroadcastAnnounce()
    fun sendAnnouncementToPeer(peerID: String)

    fun getPeerNicknames(): Map<String, String>
    fun getPeerRSSI(): Map<String, Int>
    fun getActivePeerCount(): Int
    fun hasEstablishedSession(peerID: String): Boolean
    fun getSessionState(peerID: String): com.bitchat.android.noise.NoiseSession.NoiseSessionState
    fun initiateNoiseHandshake(peerID: String)
    fun getPeerFingerprint(peerID: String): String?
    fun getPeerInfo(peerID: String): PeerInfo?
    fun updatePeerInfo(
        peerID: String,
        nickname: String,
        noisePublicKey: ByteArray,
        signingPublicKey: ByteArray,
        isVerified: Boolean
    ): Boolean
    fun getIdentityFingerprint(): String
    fun getStaticNoisePublicKey(): ByteArray?
    fun shouldShowEncryptionIcon(peerID: String): Boolean
    fun getEncryptedPeers(): List<String>

    fun getDeviceAddressForPeer(peerID: String): String?
    fun getDeviceAddressToPeerMapping(): Map<String, String>
    fun printDeviceAddressesForPeers(): String
    fun getDebugStatus(): String

    fun clearAllInternalData()
    fun clearAllEncryptionData()

    // Creator-managed E2EE private groups (BLE-mesh only; other transports no-op).
    fun listGroups(): List<com.bitchat.android.groups.BitchatGroup> = emptyList()
    fun getGroup(groupId: ByteArray): com.bitchat.android.groups.BitchatGroup? = null
    fun createGroup(name: String): com.bitchat.android.groups.BitchatGroup? = null
    fun inviteToGroup(groupId: ByteArray, peerID: String): String? = "groups are not supported on this transport"
    fun removeFromGroup(groupId: ByteArray, peerID: String): String? = "groups are not supported on this transport"
    fun leaveGroup(groupId: ByteArray) {}
    fun sendGroupMessage(groupId: ByteArray, content: String): String? = "groups are not supported on this transport"
}
