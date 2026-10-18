package com.bitchat.android.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ChannelTextPrefixTest {

    @Test
    fun `encode with no channel returns content unchanged`() {
        assertEquals("hello world", ChannelTextPrefix.encode("hello world", null))
    }

    @Test
    fun `encode with a channel prepends the visible prefix`() {
        assertEquals("#general: hello world", ChannelTextPrefix.encode("hello world", "#general"))
    }

    @Test
    fun `decode round trips a channel-tagged message`() {
        val wire = ChannelTextPrefix.encode("hello world", "#general")
        val (channel, content) = ChannelTextPrefix.decode(wire)
        assertEquals("#general", channel)
        assertEquals("hello world", content)
    }

    @Test
    fun `decode of plain text with no prefix returns null channel and original text`() {
        val (channel, content) = ChannelTextPrefix.decode("just a normal message")
        assertNull(channel)
        assertEquals("just a normal message", content)
    }

    @Test
    fun `decode preserves multi-line content after the prefix`() {
        val (channel, content) = ChannelTextPrefix.decode("#dev: line one\nline two")
        assertEquals("#dev", channel)
        assertEquals("line one\nline two", content)
    }

    @Test
    fun `decode does not match a bare hashtag with no colon`() {
        val (channel, content) = ChannelTextPrefix.decode("#justahashtag no colon here")
        assertNull(channel)
        assertEquals("#justahashtag no colon here", content)
    }

    @Test
    fun `decode is fooled by ordinary text matching the pattern, a known, accepted tradeoff`() {
        // Documents the real ambiguity: a message that was never meant to tag a channel,
        // but happens to look like "#word: rest", gets misread as one. No dedicated wire
        // field exists to disambiguate, see ChannelTextPrefix's doc comment.
        val (channel, content) = ChannelTextPrefix.decode("#not-a-channel: this was just a sentence")
        assertEquals("#not-a-channel", channel)
        assertEquals("this was just a sentence", content)
    }
}
