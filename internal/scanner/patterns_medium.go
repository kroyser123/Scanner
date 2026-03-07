package scanner
<<<<<<< HEAD
=======

var MediumPatterns = []*Pattern{
	// Slack Webhook
	MustNewPattern("slack-webhook", "Slack Webhook", LevelMedium,
		[]string{"hooks.slack.com"},
		"https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
	),

	// Discord Webhook
	MustNewPattern("discord-webhook", "Discord Webhook", LevelMedium,
		[]string{"discord.com/api/webhooks"},
		"https://discord\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
	),

	// Microsoft Teams Webhook
	MustNewPattern("teams-webhook", "Microsoft Teams Webhook", LevelMedium,
		[]string{"office.com/webhook", "teams.microsoft.com"},
		"https://[a-zA-Z0-9.-]+\\.webhook\\.office\\.com/[A-Za-z0-9/_-]+",
	),

	// GitHub Webhook
	MustNewPattern("github-webhook", "GitHub Webhook", LevelMedium,
		[]string{"github.com/webhooks"},
		"https://api\\.github\\.com/repos/[^/]+/[^/]+/hooks/[0-9]+",
	),

	// GitLab Webhook
	MustNewPattern("gitlab-webhook", "GitLab Webhook", LevelMedium,
		[]string{"gitlab.com/api/v4/webhooks"},
		"https://gitlab\\.com/api/v4/webhooks/[0-9]+",
	),

	// NPM Token
	MustNewPattern("npm-token", "NPM Token", LevelMedium,
		[]string{"npm_", "npm_token"},
		"npm_[A-Za-z0-9]{36}",
	),

	// NPM Auth Token
	MustNewPattern("npm-auth", "NPM Auth Token", LevelMedium,
		[]string{"_authToken", "//registry.npmjs.org"},
		"_authToken\\s*=\\s*[A-Za-z0-9-]{36}",
	),

	// Yarn Token
	MustNewPattern("yarn-token", "Yarn Token", LevelMedium,
		[]string{"yarn_registry"},
		"YARN_REGISTRY_TOKEN\\s*[:=]\\s*[A-Za-z0-9-]{36}",
	),

	// PyPI Token
	MustNewPattern("pypi-token", "PyPI Token", LevelMedium,
		[]string{"pypi", "__token__"},
		"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\\-]{50,}",
	),

	// Twine Token
	MustNewPattern("twine-token", "Twine Token", LevelMedium,
		[]string{"twine", "pypi_password"},
		"password\\s*=\\s*pypi-[A-Za-z0-9_\\-]{50,}",
	),

	// RubyGems Token
	MustNewPattern("gem-token", "RubyGems Token", LevelMedium,
		[]string{"rubygems", "gem_host"},
		"rubygems_[A-Za-z0-9]{40}",
	),

	// Packagist Token
	MustNewPattern("packagist-token", "Packagist Token", LevelMedium,
		[]string{"packagist", "composer"},
		"[0-9a-f]{40}",
	),

	// Crates.io Token
	MustNewPattern("crates-token", "Crates.io Token", LevelMedium,
		[]string{"crates.io", "cargo"},
		"cargo-[A-Za-z0-9]{32}",
	),

	// Redis URL
	MustNewPattern("redis-url", "Redis URL", LevelMedium,
		[]string{"redis://"},
		"redis://[^:]+:[^@]+@[^/]+:\\d+",
	),

	// Elasticsearch URL
	MustNewPattern("elastic-url", "Elasticsearch URL", LevelMedium,
		[]string{"elasticsearch://", "elastic:"},
		"https?://[^:]+:[^@]+@[^/]+:\\d+",
	),

	// WeatherAPI
	MustNewPattern("weatherapi", "WeatherAPI", LevelMedium,
		[]string{"weatherapi"},
		"[0-9a-f]{32}",
	),

	// Mailchimp API
	MustNewPattern("mailchimp", "Mailchimp API", LevelMedium,
		[]string{"mailchimp"},
		"[A-Za-z0-9]{32}-us[0-9]{1,2}",
	),

	// SendGrid API
	MustNewPattern("sendgrid", "SendGrid API", LevelMedium,
		[]string{"SG."},
		"SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}",
	),

	// Mattermost Webhook
	MustNewPattern("mattermost", "Mattermost Webhook", LevelMedium,
		[]string{"mattermost.com/hooks"},
		"https://[a-zA-Z0-9.-]+/hooks/[A-Za-z0-9]+",
	),
	MustNewPattern("jwt-token", "JWT Token", LevelMedium,
		[]string{"eyJ", "jwt", "JWT"},
		"eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
	),

	//  JWT в Authorization header
	MustNewPattern("jwt-auth-header", "JWT Auth Header", LevelMedium,
		[]string{"Bearer eyJ", "authorization"},
		"Bearer\\s+eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
	),

	//  JWT в cookie
	MustNewPattern("jwt-cookie", "JWT Cookie", LevelMedium,
		[]string{"token=", "jwt="},
		"(?:token|jwt|session)=eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
	),

	//  JWT в JSON
	MustNewPattern("jwt-json", "JWT in JSON", LevelMedium,
		[]string{"\"token\"", "\"jwt\""},
		"\"(?:token|jwt|access_token)\"\\s*:\\s*\"eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\"",
	),

	//  JWT в переменных окружения
	MustNewPattern("jwt-env", "JWT Environment Variable", LevelMedium,
		[]string{"JWT_TOKEN", "ACCESS_TOKEN"},
		"(?:JWT|ACCESS)_TOKEN\\s*[:=]\\s*[\"']?eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
	),
	MustNewPattern("telegram-user-token", "Telegram User Token", LevelMedium,
    []string{"tg", "telegram"},
    "[0-9]{8,10}:[A-Za-z0-9_-]{35}",
),
}
>>>>>>> d368b1247ac28049a0fc6d8be74855a50d3f7e85
