package scanner

var LowPatterns = []*Pattern{
	// ========== ТЕСТОВЫЕ КЛЮЧИ ==========

	// 1. Stripe Test Key
	MustNewPattern("stripe-test", "Stripe Test Key", LevelLow,
		[]string{"sk_test"},
		"sk_test_[0-9a-zA-Z]{24,}",
	),

	// 2. Stripe Publishable Key
	MustNewPattern("stripe-publishable", "Stripe Publishable Key", LevelLow,
		[]string{"pk_live", "pk_test"},
		"pk_[a-z]+_[0-9a-zA-Z]{24,}",
	),

	// 3. PayPal Sandbox
	MustNewPattern("paypal-sandbox", "PayPal Sandbox", LevelLow,
		[]string{"sb-", "sandbox"},
		"sb-[A-Za-z0-9_-]{30,}",
	),

	// 4. Square Test Key
	MustNewPattern("square-test", "Square Test Key", LevelLow,
		[]string{"sq0test"},
		"sq0test-[A-Za-z0-9_-]{22,}",
	),
	// 5. Example API Key
	MustNewPattern("example-key", "Example API Key", LevelLow,
		[]string{"example", "your-api-key"},
		"YOUR_API_KEY|your-api-key|example-key",
	),
	MustNewPattern("demo-secret", "Demo Secret", LevelLow,
		[]string{"demo", "sample"},
		"demo[_-]?(?:key|secret|token)|sample[_-]?(?:key|secret|token)",
	),
	// 6. Test Password
	MustNewPattern("test-password", "Test Password", LevelLow,
		[]string{"password123", "qwerty", "123456"},
		"password123|qwerty|123456|admin123|testpass",
	),

	// 7. Test Email
	MustNewPattern("test-email", "Test Email", LevelLow,
		[]string{"test@", "@example.com"},
		"test@example\\.com|test@test\\.com|.*@example\\.com",
	),

	// 8. Test User
	MustNewPattern("test-user", "Test User", LevelLow,
		[]string{"testuser", "guest"},
		"testuser|guest|demo@example\\.com",
	),
	// 9. Log Level (не секрет)
	MustNewPattern("log-level", "Log Level", LevelLow,
		[]string{"LOG_LEVEL"},
		"LOG_LEVEL\\s*=\\s*(debug|info|warn|error)",
	),
}
