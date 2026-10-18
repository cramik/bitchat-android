package com.bitchat.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bitchat.android.R
import com.bitchat.android.core.ui.component.sheet.BitchatBottomSheet
import com.bitchat.android.core.ui.component.sheet.BitchatSheetTitle
import com.bitchat.android.core.ui.component.sheet.BitchatSheetTopBar
import com.bitchat.android.core.ui.component.sheet.LocalSheetDismiss
import com.bitchat.android.groups.BitchatGroup
import com.bitchat.android.groups.GroupMember
import com.bitchat.android.ui.theme.BitchatFontFamily

/**
 * Groups sheet: a Compose picker/manager for creator-managed E2EE private groups,
 * presented the same way [LocationChannelsSheet] presents channels/geohashes, a
 * tap-to-switch list of what you're in, plus a "Create Group" affordance.
 *
 * Deliberately does NOT offer a "type a name to join" row the way channels/geohashes
 * do: groups are invite-only (see GroupCoordinator.inviteToGroup / CommandProcessor's
 * `/group invite`), so the only way into a group is being added by its creator. This
 * sheet is purely an additional UI on top of the same MeshService group API the
 * `/group ...` text commands already exercise, see CommandProcessor.handleGroupCommand,
 * which keeps working unmodified alongside this.
 *
 * `[Bracket]` styling marks a group's name everywhere it appears here, mirroring the
 * `#channel` / `#geohash` conventions used elsewhere so the three destination kinds stay
 * visually distinct.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupsSheet(
    isPresented: Boolean,
    onDismiss: () -> Unit,
    viewModel: ChatViewModel,
    modifier: Modifier = Modifier
) {
    if (!isPresented) return

    val myFingerprint = remember { viewModel.getMyFingerprint() }
    var groups by remember { mutableStateOf(viewModel.listGroups()) }
    var detailGroupId by remember { mutableStateOf<ByteArray?>(null) }
    var showCreateDialog by remember { mutableStateOf(false) }
    var createNameInput by rememberSaveable { mutableStateOf("") }

    fun refresh() {
        groups = viewModel.listGroups()
    }

    LaunchedEffect(isPresented) {
        if (isPresented) refresh()
    }

    val activeGroupId by viewModel.activeGroupId.collectAsStateWithLifecycle()
    val detailGroup = detailGroupId?.let { id -> groups.firstOrNull { it.groupId.contentEquals(id) } }

    BitchatBottomSheet(
        modifier = modifier,
        onDismissRequest = onDismiss
    ) {
        val dismiss = LocalSheetDismiss.current

        Box(modifier = Modifier.fillMaxWidth()) {
            if (detailGroup == null) {
                GroupsListContent(
                    groups = groups,
                    activeGroupId = activeGroupId,
                    myFingerprint = myFingerprint,
                    onSelect = { group ->
                        viewModel.setActiveGroup(group.groupId)
                        dismiss?.invoke() ?: onDismiss()
                    },
                    onManage = { group -> detailGroupId = group.groupId },
                    onCreateClick = { showCreateDialog = true }
                )
            } else {
                GroupDetailContent(
                    group = detailGroup,
                    myFingerprint = myFingerprint,
                    isActive = activeGroupId?.contentEquals(detailGroup.groupId) == true,
                    onActivate = {
                        viewModel.setActiveGroup(detailGroup.groupId)
                        dismiss?.invoke() ?: onDismiss()
                    },
                    onStopTyping = { viewModel.stopTypingIntoGroup() },
                    onLeave = {
                        viewModel.leaveGroupById(detailGroup.groupId)
                        detailGroupId = null
                        refresh()
                    },
                    onInvite = { nickname ->
                        val reason = viewModel.inviteToGroup(detailGroup.groupId, nickname)
                        refresh()
                        reason
                    },
                    onRemove = { nickname ->
                        val reason = viewModel.removeFromGroup(detailGroup.groupId, nickname)
                        refresh()
                        reason
                    }
                )
            }

            BitchatSheetTopBar(
                onClose = onDismiss,
                modifier = Modifier.align(Alignment.TopCenter),
                title = {
                    BitchatSheetTitle(text = detailGroup?.let { "[${it.name}]" } ?: "Groups")
                },
                navigationIcon = if (detailGroup != null) {
                    {
                        IconButton(onClick = { detailGroupId = null }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to groups")
                        }
                    }
                } else null
            )
        }
    }

    if (showCreateDialog) {
        val colorScheme = MaterialTheme.colorScheme
        AlertDialog(
            onDismissRequest = {
                showCreateDialog = false
                createNameInput = ""
            },
            title = {
                Text(
                    text = "Create Group",
                    style = MaterialTheme.typography.titleMedium,
                    color = colorScheme.onSurface
                )
            },
            text = {
                OutlinedTextField(
                    value = createNameInput,
                    onValueChange = { createNameInput = it },
                    singleLine = true,
                    label = { Text("Group name", style = MaterialTheme.typography.bodyMedium) },
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = BitchatFontFamily),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = colorScheme.primary,
                        unfocusedBorderColor = colorScheme.outline
                    )
                )
            },
            confirmButton = {
                TextButton(
                    enabled = createNameInput.isNotBlank(),
                    onClick = {
                        val name = createNameInput.trim()
                        val group = viewModel.createGroupAndActivate(name)
                        showCreateDialog = false
                        createNameInput = ""
                        if (group != null) {
                            onDismiss()
                        } else {
                            refresh()
                        }
                    }
                ) {
                    Text("Create")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    showCreateDialog = false
                    createNameInput = ""
                }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
private fun GroupsListContent(
    groups: List<BitchatGroup>,
    activeGroupId: ByteArray?,
    myFingerprint: String,
    onSelect: (BitchatGroup) -> Unit,
    onManage: (BitchatGroup) -> Unit,
    onCreateClick: () -> Unit
) {
    val colorScheme = MaterialTheme.colorScheme

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(top = 72.dp, bottom = 32.dp)
    ) {
        item(key = "groups_header") {
            SheetIconSectionHeader(
                iconRes = R.drawable.ic_spec_people,
                title = "Your Groups",
                subtitle = "Invite-only E2EE groups. Ask a creator to invite you, there's no name to type your way in."
            )
        }

        if (groups.isEmpty()) {
            item(key = "empty") {
                Text(
                    text = "You're not in any groups yet.",
                    fontSize = 13.sp,
                    fontFamily = BitchatFontFamily,
                    color = colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(
                        horizontal = AboutHorizontalPadding + SheetRowHorizontal,
                        vertical = 12.dp
                    )
                )
            }
        } else {
            item(key = "groups_card") {
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = AboutHorizontalPadding)
                        .padding(top = 10.dp),
                    color = colorScheme.surface,
                    shape = AboutCardShape
                ) {
                    Column {
                        groups.forEachIndexed { index, group ->
                            if (index > 0) SheetCardDivider()
                            GroupRow(
                                group = group,
                                isActive = activeGroupId?.contentEquals(group.groupId) == true,
                                isCreator = group.creatorFingerprint == myFingerprint,
                                onClick = { onSelect(group) },
                                onManageClick = { onManage(group) }
                            )
                        }
                    }
                }
            }
        }

        item(key = "create_button") {
            SheetDestructiveButton(
                text = "Create Group",
                isDestructive = false,
                onClick = onCreateClick,
                modifier = Modifier.padding(
                    start = AboutHorizontalPadding,
                    end = AboutHorizontalPadding,
                    top = 20.dp
                )
            )
        }
    }
}

@Composable
private fun GroupRow(
    group: BitchatGroup,
    isActive: Boolean,
    isCreator: Boolean,
    onClick: () -> Unit,
    onManageClick: () -> Unit
) {
    val colorScheme = MaterialTheme.colorScheme

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = SheetRowHorizontal, vertical = SheetRowVertical),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier.size(SheetRowLeadingSlot),
            contentAlignment = Alignment.Center
        ) {
            if (isActive) {
                Box(
                    modifier = Modifier
                        .size(SheetRowSelectedDot)
                        .background(colorScheme.primary, CircleShape)
                )
            }
        }

        Spacer(modifier = Modifier.width(SheetRowLeadingGutter))

        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            Text(
                text = "[${group.name}]",
                fontSize = 14.sp,
                fontFamily = BitchatFontFamily,
                fontWeight = if (isActive) FontWeight.SemiBold else FontWeight.Medium,
                color = if (isActive) colorScheme.primary else colorScheme.onSurface
            )
            val memberWord = if (group.members.size == 1) "member" else "members"
            val subtitle = "${group.members.size} $memberWord" + if (isCreator) " • you created this" else ""
            Text(
                text = subtitle,
                fontSize = 12.sp,
                fontFamily = BitchatFontFamily,
                color = colorScheme.onSurfaceVariant
            )
        }

        IconButton(onClick = onManageClick) {
            Icon(
                imageVector = Icons.Filled.ChevronRight,
                contentDescription = "Manage ${group.name}",
                tint = colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun GroupDetailContent(
    group: BitchatGroup,
    myFingerprint: String,
    isActive: Boolean,
    onActivate: () -> Unit,
    onStopTyping: () -> Unit,
    onLeave: () -> Unit,
    onInvite: (String) -> String?,
    onRemove: (String) -> String?
) {
    val colorScheme = MaterialTheme.colorScheme
    val isCreator = group.creatorFingerprint == myFingerprint
    var inviteNickname by rememberSaveable(group.groupId.contentHashCode()) { mutableStateOf("") }
    // (succeeded, message), cleared whenever a new action runs.
    var feedback by remember(group.groupId.contentHashCode()) { mutableStateOf<Pair<Boolean, String>?>(null) }
    var showLeaveConfirm by remember(group.groupId.contentHashCode()) { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(top = 72.dp, bottom = 32.dp)
    ) {
        item(key = "activate_row") {
            Column(modifier = Modifier.padding(horizontal = AboutHorizontalPadding)) {
                if (!isActive) {
                    SheetDestructiveButton(
                        text = "Type Here",
                        isDestructive = false,
                        onClick = onActivate
                    )
                } else {
                    Text(
                        text = "Typed messages currently go to this group.",
                        fontSize = 12.sp,
                        fontFamily = BitchatFontFamily,
                        color = colorScheme.primary,
                        modifier = Modifier.padding(vertical = 8.dp)
                    )
                }
            }
        }

        item(key = "members_header") {
            AboutSectionLabel(text = "Members (${group.members.size})")
        }

        item(key = "members_card") {
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = AboutHorizontalPadding),
                color = colorScheme.surface,
                shape = AboutCardShape
            ) {
                Column {
                    group.members.forEachIndexed { index, member ->
                        if (index > 0) SheetCardDivider()
                        MemberRow(
                            member = member,
                            isCreator = member.fingerprint == group.creatorFingerprint,
                            isSelf = member.fingerprint == myFingerprint,
                            canRemove = isCreator && member.fingerprint != myFingerprint,
                            onRemove = {
                                val reason = onRemove(member.nickname)
                                feedback = if (reason != null) {
                                    false to reason
                                } else {
                                    true to "Removed ${member.nickname}"
                                }
                            }
                        )
                    }
                }
            }
        }

        if (isCreator) {
            item(key = "invite_header") {
                AboutSectionLabel(text = "Invite")
            }
            item(key = "invite_row") {
                InviteRow(
                    nickname = inviteNickname,
                    onNicknameChange = { inviteNickname = it },
                    onInvite = {
                        val name = inviteNickname.trim()
                        if (name.isNotEmpty()) {
                            val reason = onInvite(name)
                            feedback = if (reason != null) {
                                false to reason
                            } else {
                                true to "Invited $name"
                            }
                            if (reason == null) inviteNickname = ""
                        }
                    }
                )
            }
        }

        feedback?.let { (success, message) ->
            item(key = "feedback") {
                Text(
                    text = message,
                    fontSize = 12.sp,
                    fontFamily = BitchatFontFamily,
                    color = if (success) colorScheme.primary else colorScheme.error,
                    modifier = Modifier.padding(
                        horizontal = AboutHorizontalPadding + SheetRowHorizontal,
                        vertical = 8.dp
                    )
                )
            }
        }

        item(key = "exit_actions") {
            Column(
                modifier = Modifier.padding(
                    start = AboutHorizontalPadding,
                    end = AboutHorizontalPadding,
                    top = 20.dp
                ),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                if (isActive) {
                    SheetDestructiveButton(
                        text = "Stop Typing Here",
                        isDestructive = false,
                        onClick = onStopTyping
                    )
                }
                if (!showLeaveConfirm) {
                    SheetDestructiveButton(
                        text = "Leave Group",
                        isDestructive = true,
                        onClick = { showLeaveConfirm = true }
                    )
                } else {
                    Text(
                        text = "Leave '${group.name}'? You'll need a new invite from the creator to rejoin.",
                        fontSize = 12.sp,
                        fontFamily = BitchatFontFamily,
                        color = colorScheme.error
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        SheetDestructiveButton(
                            text = "Confirm Leave",
                            isDestructive = true,
                            onClick = onLeave,
                            modifier = Modifier.weight(1f)
                        )
                        SheetDestructiveButton(
                            text = "Cancel",
                            isDestructive = false,
                            onClick = { showLeaveConfirm = false },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun MemberRow(
    member: GroupMember,
    isCreator: Boolean,
    isSelf: Boolean,
    canRemove: Boolean,
    onRemove: () -> Unit
) {
    val colorScheme = MaterialTheme.colorScheme

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = SheetRowHorizontal, vertical = SheetRowVertical),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier.size(SheetRowLeadingSlot),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                painter = painterResource(R.drawable.ic_spec_person),
                contentDescription = null,
                tint = colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp)
            )
        }

        Spacer(modifier = Modifier.width(SheetRowLeadingGutter))

        Column(modifier = Modifier.weight(1f)) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = member.nickname,
                    fontSize = 14.sp,
                    fontFamily = BitchatFontFamily,
                    fontWeight = FontWeight.Medium,
                    color = colorScheme.onSurface
                )
                if (isSelf) {
                    Text(
                        text = "(you)",
                        fontSize = 11.sp,
                        fontFamily = BitchatFontFamily,
                        color = colorScheme.onSurfaceVariant
                    )
                }
            }
            if (isCreator) {
                Text(
                    text = "creator",
                    fontSize = 11.sp,
                    fontFamily = BitchatFontFamily,
                    color = colorScheme.primary
                )
            }
        }

        if (canRemove) {
            TextButton(onClick = onRemove) {
                Text(
                    text = "Remove",
                    color = colorScheme.error,
                    fontFamily = BitchatFontFamily,
                    fontSize = 12.sp
                )
            }
        }
    }
}

@Composable
private fun InviteRow(
    nickname: String,
    onNicknameChange: (String) -> Unit,
    onInvite: () -> Unit
) {
    val colorScheme = MaterialTheme.colorScheme

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = AboutHorizontalPadding),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        OutlinedTextField(
            value = nickname,
            onValueChange = onNicknameChange,
            singleLine = true,
            modifier = Modifier.weight(1f),
            label = { Text("Nickname", style = MaterialTheme.typography.bodyMedium) },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = BitchatFontFamily),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = colorScheme.primary,
                unfocusedBorderColor = colorScheme.outline
            )
        )
        TextButton(
            enabled = nickname.isNotBlank(),
            onClick = onInvite
        ) {
            Text("Invite")
        }
    }
}
