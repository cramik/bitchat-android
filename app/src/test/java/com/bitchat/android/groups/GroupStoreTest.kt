package com.bitchat.android.groups

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.SecureRandom

private fun randomBytes(n: Int): ByteArray = ByteArray(n).also { SecureRandom().nextBytes(it) }
private fun fingerprintHex(seed: Byte): String = ByteArray(32) { seed }.joinToString("") { "%02x".format(it) }

class GroupStoreTest {

    private fun tempPath(): File {
        val file = File.createTempFile("groups-test", ".json")
        file.deleteOnExit()
        file.delete() // GroupManager should tolerate a non-existent file at construction
        return file
    }

    @Test
    fun `create group then reload from disk`() {
        val path = tempPath()
        val creator = GroupMember(fingerprintHex(1), randomBytes(32), "alice")
        val manager = GroupManager(path)
        val group = manager.createGroup("my group", creator)!!
        assertEquals(1, group.epoch)
        assertEquals(1, group.members.size)

        val reloaded = GroupManager(path)
        val reloadedGroup = reloaded.group(group.groupId)!!
        assertEquals(group.name, reloadedGroup.name)
        assertEquals(group.epoch, reloadedGroup.epoch)
        assertEquals(group.creatorFingerprint, reloadedGroup.creatorFingerprint)
        assertEquals(reloaded.key(group.groupId)!!.toList(), manager.key(group.groupId)!!.toList())
    }

    @Test
    fun `rotateKey bumps epoch and changes the key`() {
        val path = tempPath()
        val creator = GroupMember(fingerprintHex(1), randomBytes(32), "alice")
        val manager = GroupManager(path)
        val group = manager.createGroup("g", creator)!!
        val originalKey = manager.key(group.groupId)!!

        val newMember = GroupMember(fingerprintHex(2), randomBytes(32), "bob")
        val (rotated, newKey) = manager.rotateKey(group.groupId, listOf(creator, newMember))!!
        assertEquals(2, rotated.epoch)
        assertEquals(2, rotated.members.size)
        assertTrue(!originalKey.contentEquals(newKey))
        assertEquals(newKey.toList(), manager.key(group.groupId)!!.toList())
    }

    @Test
    fun `updateRoster requires the creator to remain present`() {
        val path = tempPath()
        val creator = GroupMember(fingerprintHex(1), randomBytes(32), "alice")
        val manager = GroupManager(path)
        val group = manager.createGroup("g", creator)!!

        val withoutCreator = listOf(GroupMember(fingerprintHex(2), randomBytes(32), "bob"))
        assertNull(manager.updateRoster(group.groupId, withoutCreator))

        val withCreator = listOf(creator, GroupMember(fingerprintHex(2), randomBytes(32), "bob"))
        val updated = manager.updateRoster(group.groupId, withCreator)!!
        assertEquals(2, updated.members.size)
    }

    @Test
    fun `removeGroup deletes it locally and wipe clears everything`() {
        val path = tempPath()
        val creator = GroupMember(fingerprintHex(1), randomBytes(32), "alice")
        val manager = GroupManager(path)
        val g1 = manager.createGroup("g1", creator)!!
        val g2 = manager.createGroup("g2", creator)!!

        manager.removeGroup(g1.groupId)
        assertNull(manager.group(g1.groupId))
        assertEquals(g2.groupId.toList(), manager.group(g2.groupId)!!.groupId.toList())

        manager.wipe()
        assertTrue(manager.groups.isEmpty())
        assertNull(manager.group(g2.groupId))
    }

    @Test
    fun `wipe deletes the backing file so reload starts empty`() {
        val path = tempPath()
        val creator = GroupMember(fingerprintHex(1), randomBytes(32), "alice")
        val manager = GroupManager(path)
        manager.createGroup("g", creator)
        assertTrue(path.exists())

        manager.wipe()
        assertTrue(!path.exists())
        assertTrue(GroupManager(path).groups.isEmpty())
    }

    @Test
    fun `malformed stored group is skipped without throwing`() {
        val path = tempPath()
        path.writeText(
            """{"groups":[{"group_id":"not-hex!","name":"bad","epoch":1,"creator_fingerprint":"${fingerprintHex(1)}","members":[],"key":"00"}]}"""
        )
        val manager = GroupManager(path)
        assertTrue(manager.groups.isEmpty())
    }

    @Test
    fun `upsert rejects an oversized roster`() {
        val path = tempPath()
        val creator = GroupMember(fingerprintHex(1), randomBytes(32), "alice")
        val manager = GroupManager(path)
        val tooMany = (0..GroupProtocolConstants.MAX_MEMBERS).map { GroupMember(fingerprintHex(it.toByte()), randomBytes(32), "m$it") }
        val group = BitchatGroup(randomBytes(16), "g", 1, tooMany, creator.fingerprint)
        assertTrue(!manager.upsert(group, randomBytes(32)))
    }
}
