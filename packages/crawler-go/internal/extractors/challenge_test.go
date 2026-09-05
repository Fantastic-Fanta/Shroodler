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

func TestDetectChallengeFiresOnSmallCFRayResponse(t *testing.T) {
	f := DetectChallenge(map[string]string{"cf-ray": "abc123-SJC"}, "short body", 200)
	if f == nil {
		t.Fatal("expected a challenge finding for small cf-ray response")
	}
}
