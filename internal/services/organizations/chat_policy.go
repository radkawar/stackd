package organizations

import (
	"fmt"
	"strings"
)

func chatPolicy(n *managementNode) error {
	if !managementObject(n) || len(n.children) != 1 || n.children["chatbot"] == nil || !chatSettings(n.children["chatbot"], "chatbot") {
		return fmt.Errorf("invalid chat application policy")
	}
	return nil
}

func chatSettings(n *managementNode, kind string) bool {
	if !managementObject(n) {
		return false
	}
	for field, setting := range n.children {
		valid := false
		switch field {
		case "client":
			valid = kind != "chatbot" && managementScalarSetting(setting, func(v string) bool { return v == "enabled" || v == "disabled" })
		case "platforms":
			valid = kind == "chatbot" && managementObject(setting)
			for platform, settings := range setting.children {
				valid = valid && (platform == "slack" || platform == "microsoft_teams" || platform == "chime") && chatSettings(settings, platform)
			}
		case "default":
			if kind == "chatbot" {
				valid = chatSettings(setting, "default")
			} else if kind == "slack" || kind == "microsoft_teams" {
				valid = chatRoles(setting, kind)
			}
		case "workspaces":
			valid = kind == "slack" && managementStringList(setting, func(v string) bool { return v == "*" || chatWorkspaceID.MatchString(v) }, false)
		case "tenants":
			valid = kind == "microsoft_teams" && managementObject(setting)
			for tenant, teams := range setting.children {
				valid = valid && (tenant == "*" || chatUUID(tenant)) && managementStringList(teams, func(v string) bool { return v == "*" || chatUUID(v) }, false)
			}
		case "overrides":
			valid = managementObject(setting) && (kind == "slack" || kind == "microsoft_teams")
			for identifier, override := range setting.children {
				if kind == "slack" {
					valid = valid && chatWorkspaceID.MatchString(identifier) && chatRoles(override, kind)
				} else {
					valid = valid && chatUUID(identifier) && managementObject(override)
					for team, roles := range override.children {
						valid = valid && chatUUID(team) && chatRoles(roles, kind)
					}
				}
			}
		}
		if !valid {
			return false
		}
	}
	return true
}

func chatRoles(n *managementNode, platform string) bool {
	if !managementObject(n) {
		return false
	}
	for field, setting := range n.children {
		switch field {
		case "supported_channel_types":
			if platform != "slack" || !managementStringList(setting, func(v string) bool { return v == "public" || v == "private" }, false) {
				return false
			}
		case "supported_role_settings":
			if !managementStringList(setting, func(v string) bool { return v == "user_role" || v == "channel_role" }, false) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func chatUUID(value string) bool {
	// Organizations accepts only lowercase UUIDs, unlike the Chatbot SDK shape.
	return value == strings.ToLower(value) && chatTeamsID.MatchString(value)
}

// Field names are case-insensitive; workspace and tenant/team identifiers retain
// their spelling. The parser has already rejected case-insensitive duplicates.
func normalizeChatFields(n *managementNode) {
	foldChatFields(n)
	chatbot := n.children["chatbot"]
	if chatbot == nil {
		return
	}
	foldChatFields(chatbot)
	foldChatFields(chatbot.children["default"])
	platforms := chatbot.children["platforms"]
	if platforms == nil {
		return
	}
	foldChatFields(platforms)
	for platform, settings := range platforms.children {
		foldChatFields(settings)
		foldChatFields(settings.children["default"])
		if overrides := settings.children["overrides"]; overrides != nil {
			for _, override := range overrides.children {
				if platform == "microsoft_teams" {
					for _, roles := range override.children {
						foldChatFields(roles)
					}
				} else {
					foldChatFields(override)
				}
			}
		}
	}
}

func foldChatFields(n *managementNode) {
	if n == nil || n.children == nil {
		return
	}
	fields := make(map[string]*managementNode, len(n.children))
	for key, value := range n.children {
		fields[strings.ToLower(key)] = value
	}
	n.children = fields
}
