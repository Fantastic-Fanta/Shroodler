package extractors

import "testing"

func TestDetectChallengeFromBodyMarker(t *testing.T) {
	f := DetectChallenge(map[string]string{}, "<html>Just a moment...</html>", 503)
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
	f := DetectChallenge(map[string]string{"cf-ray": "abc123-SJC"}, "<html><body>"+body+"</body></html>", 200)
	if f != nil {
		t.Fatalf("cf-ray alone on a normal page should not fire, got %#v", f)
	}
}

func TestDetectChallengeIgnoresCFRayEvenOnSmall200Response(t *testing.T) {
	// Small 200 API responses are the norm on Cloudflare-fronted sites; cf-ray
	// alone must not reclassify them as a challenge regardless of size.
	f := DetectChallenge(map[string]string{"cf-ray": "abc123-SJC"}, "short body", 200)
	if f != nil {
		t.Fatalf("cf-ray alone on a 200 response should not fire, got %#v", f)
	}
}

func TestDetectChallengeFiresOnCFRayWithBlockStatus(t *testing.T) {
	f := DetectChallenge(map[string]string{"cf-ray": "abc123-SJC"}, "short body", 403)
	if f == nil {
		t.Fatal("expected a challenge finding for cf-ray + 403")
	}
}

func TestDetectChallengeIgnoresRecaptchaWidgetOnOrdinaryForm(t *testing.T) {
	body := `<form><div class="g-recaptcha" data-sitekey="x"></div></form>`
	if f := DetectChallenge(map[string]string{}, body, 200); f != nil {
		t.Fatalf("recaptcha tag on a normal 200 form should not fire, got %#v", f)
	}
}

func TestDetectChallengeFiresOnRecaptchaTagWithBlockStatus(t *testing.T) {
	body := `<form><div class="g-recaptcha" data-sitekey="x"></div></form>`
	if f := DetectChallenge(map[string]string{}, body, 403); f == nil {
		t.Fatal("expected a challenge finding for recaptcha tag + 403")
	}
}
