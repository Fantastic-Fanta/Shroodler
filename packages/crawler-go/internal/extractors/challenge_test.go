package extractors

import "testing"

func TestDetectChallengeFromBodyMarker(t *testing.T) {
	f := DetectChallenge(map[string]string{}, "<html>Just a moment...</html>", 503, nil)
	if f == nil {
		t.Fatal("expected a challenge finding")
	}
	if f.Category != "waf-challenge" || f.ID != "waf-challenge-detected" {
		t.Fatalf("unexpected finding %#v", f)
	}
}

func TestDetectChallengeIgnoresPlainCFRayOnNormalPage(t *testing.T) {
	body := ""
	for i := 0; i < 500; i++ {
		body += "normal page content "
	}
	f := DetectChallenge(map[string]string{"cf-ray": "abc123-SJC"}, "<html><body>"+body+"</body></html>", 200, nil)
	if f != nil {
		t.Fatalf("cf-ray alone on a normal page should not fire, got %#v", f)
	}
}

func TestDetectChallengeIgnoresCFRayEvenOnSmall200Response(t *testing.T) {
	// Small 200 API responses are the norm on Cloudflare-fronted sites; cf-ray
	// alone must not reclassify them as a challenge regardless of size.
	f := DetectChallenge(map[string]string{"cf-ray": "abc123-SJC"}, "short body", 200, nil)
	if f != nil {
		t.Fatalf("cf-ray alone on a 200 response should not fire, got %#v", f)
	}
}

func TestDetectChallengeFiresOnCFRayWithBlockStatus(t *testing.T) {
	f := DetectChallenge(map[string]string{"cf-ray": "abc123-SJC"}, "short body", 403, nil)
	if f == nil {
		t.Fatal("expected a challenge finding for cf-ray + 403")
	}
}

func TestDetectChallengeIgnoresRecaptchaWidgetOnOrdinaryForm(t *testing.T) {
	body := `<form><div class="g-recaptcha" data-sitekey="x"></div></form>`
	if f := DetectChallenge(map[string]string{}, body, 200, nil); f != nil {
		t.Fatalf("recaptcha tag on a normal 200 form should not fire, got %#v", f)
	}
}

func TestDetectChallengeFiresOnRecaptchaTagWithBlockStatus(t *testing.T) {
	body := `<form><div class="g-recaptcha" data-sitekey="x"></div></form>`
	if f := DetectChallenge(map[string]string{}, body, 403, nil); f == nil {
		t.Fatal("expected a challenge finding for recaptcha tag + 403")
	}
}

func TestDetectChallengeFiresOnClearanceCookieWithBlockStatus(t *testing.T) {
	cookies := []string{"cf_clearance=abcdef; path=/; secure"}
	f := DetectChallenge(map[string]string{}, "short body", 403, cookies)
	if f == nil {
		t.Fatal("expected a challenge finding for cf_clearance cookie + 403")
	}
	if f.Evidence == nil || *f.Evidence != "Cloudflare" {
		t.Fatalf("expected Cloudflare evidence, got %#v", f.Evidence)
	}
}

func TestDetectChallengeIgnoresClearanceCookieOn200(t *testing.T) {
	cookies := []string{"cf_clearance=abcdef; path=/; secure"}
	if f := DetectChallenge(map[string]string{}, "short body", 200, cookies); f != nil {
		t.Fatalf("cf_clearance cookie alone on a 200 should not fire, got %#v", f)
	}
}

func TestHasChallengeCookie(t *testing.T) {
	if !HasChallengeCookie([]string{"cf_clearance=abcdef; path=/"}) {
		t.Fatal("expected cf_clearance to be recognized")
	}
	if HasChallengeCookie([]string{"session=abc123; path=/"}) {
		t.Fatal("ordinary session cookie should not be recognized as a challenge cookie")
	}
}
