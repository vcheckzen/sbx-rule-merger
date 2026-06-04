package ruleset

type CollectResult struct {
	Domains      []string
	DomainSuffix []string
	IPCIDR       []string
}

type Group struct {
	Name  string
	Items []CollectResult
}
