# A credential shared by two profiles, with a rule pinned to one of
# them: the round trip must keep the profile predicate.
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}

endpoint "https" "gitlab" {
  hosts = ["gitlab.com"]
}

credential "bearer_token" "gitlab-shared" {
  endpoint = https.gitlab
}

profile "team-a" {
  credentials = [bearer_token.gitlab-shared]
}

profile "team-b" {
  credentials = [bearer_token.gitlab-shared]
}

rule "team-a-allow-reads" {
  endpoint   = https.gitlab
  priority   = 50
  credential = bearer_token.gitlab-shared
  profile    = profile.team-a
  condition  = "http.method == 'GET'"
  verdict    = "allow"
}

rule "team-a-preapprove-notes" {
  endpoint      = https.gitlab
  priority      = 50
  profile       = profile.team-a
  yield_to_deny = true
  condition     = "http.path.endsWith('/notes')"
  verdict       = "allow"
}
