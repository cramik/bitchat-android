package com.bitchat.android.groups

import android.util.Log
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import java.io.File
import java.security.SecureRandom

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun hexToBytesOrNull(hex: String): ByteArray? {
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

private data class StoredMember(val fingerprint: String, @SerializedName("signing_key") val signingKeyHex: String, val nickname: String)

private data class StoredGroup(
    @SerializedName("group_id") val groupIdHex: String,
    val name: String,
    val epoch: Int,
    @SerializedName("creator_fingerprint") val creatorFingerprint: String,
    val members: List<StoredMember>,
    val key: String
)

private data class StoredGroupsFile(val groups: List<StoredGroup>)

/**
 * Local persistent store for groups this device is a member of:
 * metadata (roster, name, epoch) and the current symmetric key together,
 * matching bitchat-reference's `GroupStore.swift` in shape and mirroring
 * bitchat-win's `GroupManager` (`bitchat/groups.py`) byte-for-byte on the
 * wire, though not on disk (this uses Gson JSON, that uses stdlib json;
 * both produce the same logical document).
 *
 * One real, deliberate deviation worth flagging: iOS keeps the symmetric
 * key in the OS Keychain (hardware-backed on real devices) separately from
 * the JSON metadata, specifically so the key gets extra at-rest protection.
 * This store takes a plain [File] rather than reaching into Android
 * KeyStore/EncryptedSharedPreferences itself, matching the same deviation
 * already accepted on the Windows port, a future improvement would be
 * wiring the key material specifically through EncryptedFile/Keystore.
 */
class GroupManager(private val path: File) {
    companion object {
        private const val TAG = "GroupManager"
    }

    private val gson = Gson()
    private val secureRandom = SecureRandom()
    private val groupsById = linkedMapOf<String, BitchatGroup>() // groupId.hex() -> BitchatGroup
    private val keysById = linkedMapOf<String, ByteArray>() // groupId.hex() -> current epoch key

    init {
        load()
    }

    val groups: List<BitchatGroup>
        @Synchronized get() = groupsById.values.toList()

    @Synchronized
    fun group(groupId: ByteArray): BitchatGroup? = groupsById[groupId.toHex()]

    @Synchronized
    fun groupForPeerId(peerIdHex: String): BitchatGroup? {
        val groupId = groupIdFromPeerId(peerIdHex) ?: return null
        return group(groupId)
    }

    @Synchronized
    fun key(groupId: ByteArray): ByteArray? = keysById[groupId.toHex()]

    @Synchronized
    fun createGroup(name: String, creator: GroupMember): BitchatGroup? {
        val groupId = randomBytes(GroupProtocolConstants.GROUP_ID_LENGTH)
        val key = randomBytes(GroupProtocolConstants.KEY_LENGTH)
        val group = BitchatGroup(groupId, name, epoch = 1, members = listOf(creator), creatorFingerprint = creator.fingerprint)
        return if (upsert(group, key)) group else null
    }

    @Synchronized
    fun upsert(group: BitchatGroup, key: ByteArray): Boolean {
        if (group.groupId.size != GroupProtocolConstants.GROUP_ID_LENGTH ||
            key.size != GroupProtocolConstants.KEY_LENGTH ||
            group.members.isEmpty() ||
            group.members.size > GroupProtocolConstants.MAX_MEMBERS ||
            group.creator == null
        ) return false
        val idHex = group.groupId.toHex()
        groupsById[idHex] = group
        keysById[idHex] = key
        save()
        return true
    }

    @Synchronized
    fun updateRoster(groupId: ByteArray, members: List<GroupMember>): BitchatGroup? {
        val existing = group(groupId) ?: return null
        if (members.isEmpty() || members.size > GroupProtocolConstants.MAX_MEMBERS ||
            members.none { it.fingerprint == existing.creatorFingerprint }
        ) return null
        val updated = existing.copy(members = members)
        groupsById[groupId.toHex()] = updated
        save()
        return updated
    }

    @Synchronized
    fun rotateKey(groupId: ByteArray, members: List<GroupMember>): Pair<BitchatGroup, ByteArray>? {
        val existing = group(groupId) ?: return null
        val newKey = randomBytes(GroupProtocolConstants.KEY_LENGTH)
        val rotated = BitchatGroup(existing.groupId, existing.name, existing.epoch + 1, members, existing.creatorFingerprint)
        return if (upsert(rotated, newKey)) rotated to newKey else null
    }

    @Synchronized
    fun removeGroup(groupId: ByteArray) {
        groupsById.remove(groupId.toHex())
        keysById.remove(groupId.toHex())
        save()
    }

    @Synchronized
    fun wipe() {
        groupsById.clear()
        keysById.clear()
        save()
    }

    private fun randomBytes(length: Int): ByteArray {
        val out = ByteArray(length)
        secureRandom.nextBytes(out)
        return out
    }

    // persistence

    private fun save() {
        try {
            if (groupsById.isEmpty()) {
                if (path.exists()) path.delete()
                return
            }
            val data = StoredGroupsFile(
                groups = groupsById.values.map { group ->
                    StoredGroup(
                        groupIdHex = group.groupId.toHex(),
                        name = group.name,
                        epoch = group.epoch,
                        creatorFingerprint = group.creatorFingerprint,
                        members = group.members.map { StoredMember(it.fingerprint, it.signingKey.toHex(), it.nickname) },
                        key = keysById.getValue(group.groupId.toHex()).toHex()
                    )
                }
            )
            path.parentFile?.mkdirs()
            path.writeText(gson.toJson(data))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save groups: ${e.message}")
        }
    }

    private fun load() {
        if (!path.isFile) return
        try {
            val data = gson.fromJson(path.readText(), StoredGroupsFile::class.java) ?: return
            for (entry in data.groups) {
                try {
                    val groupId = hexToBytesOrNull(entry.groupIdHex) ?: continue
                    if (groupId.size != GroupProtocolConstants.GROUP_ID_LENGTH) continue
                    val key = hexToBytesOrNull(entry.key) ?: continue
                    if (key.size != GroupProtocolConstants.KEY_LENGTH) continue
                    val members = entry.members.map { m ->
                        val signingKey = hexToBytesOrNull(m.signingKeyHex) ?: return@map null
                        if (signingKey.size != GroupProtocolConstants.SIGNING_KEY_LENGTH || hexToBytesOrNull(m.fingerprint)?.size != GroupProtocolConstants.FINGERPRINT_LENGTH) return@map null
                        GroupMember(m.fingerprint, signingKey, m.nickname)
                    }
                    if (members.any { it == null } || members.isEmpty()) continue
                    @Suppress("UNCHECKED_CAST")
                    val group = BitchatGroup(groupId, entry.name, entry.epoch, members as List<GroupMember>, entry.creatorFingerprint)
                    if (group.creator == null) continue
                    groupsById[group.groupId.toHex()] = group
                    keysById[group.groupId.toHex()] = key
                } catch (e: Exception) {
                    Log.w(TAG, "Skipping malformed stored group: ${e.message}")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load groups: ${e.message}")
        }
    }
}
