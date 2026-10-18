package com.bitchat.android.mesh

/**
 * Fork-only convention for scoping a public mesh broadcast to a named
 * `#channel` without changing the wire format real bitchat clients expect.
 *
 * A public MessageType.MESSAGE payload on the wire is plain UTF-8 text, so
 * the channel is encoded as a text prefix: "#general: hello" is exactly what
 * goes out as the packet payload. A client that doesn't know this convention
 * just sees ordinary readable text with a visible prefix.
 *
 * Known tradeoff: an ordinary message starting with "#someword: " is
 * misread as a channel tag by receivers using this convention. See README.
 */
object ChannelTextPrefix {
    private val PREFIX_PATTERN = Regex("^(#\\S+): ([\\s\\S]*)$")

    /** Builds the actual wire text for an outgoing message. Returns [content]
     * unchanged when [channel] is null. */
    fun encode(content: String, channel: String?): String {
        if (channel == null) return content
        return "$channel: $content"
    }

    /** Splits a decoded plain-text payload back into (channel, content) if it
     * matches the "#channel: " prefix convention, else (null, the original
     * text unchanged). */
    fun decode(text: String): Pair<String?, String> {
        val match = PREFIX_PATTERN.matchEntire(text) ?: return null to text
        val (channel, content) = match.destructured
        return channel to content
    }
}
