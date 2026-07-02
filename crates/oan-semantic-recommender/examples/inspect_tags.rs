use oan_core::ResourceType;
use oan_semantic_recommender::{
    DiscoverySuggestionContext, DiscoverySuggestionInput, RegistrationSuggestionContext,
    RegistrationSuggestionInput, SemanticRecommender,
};

fn main() {
    let recommender = SemanticRecommender::new().expect("recommender");
    let registration = recommender
        .suggest_registration_metadata(
            RegistrationSuggestionInput {
                resource_type: Some(ResourceType::Skill),
                name: "Contract Risk Review Skill".to_owned(),
                description: "Review supplier contracts, analyze clauses, and identify legal risk."
                    .to_owned(),
                endpoint: None,
                manifest_text: None,
                schema_text: None,
                locale: Some("en".to_owned()),
            },
            RegistrationSuggestionContext {
                registrar_did: "did:oan:INRG:test".to_owned(),
                allowed_domains: vec!["legal".to_owned()],
                max_authorized_domain_candidates: 6,
                max_capability_tag_candidates: 12,
            },
        )
        .expect("registration");
    println!("registration tags:");
    for tag in registration.capability_tags {
        println!("{} {}", tag.score, tag.value);
    }

    let discovery = recommender
        .suggest_discovery_query(
            DiscoverySuggestionInput {
                query:
                    "Find an MCP server for smart contract security audit and vulnerability detection"
                        .to_owned(),
                current_resource_type: None,
                current_protocol: None,
                current_capability_tags: vec![],
                locale: Some("en".to_owned()),
            },
            DiscoverySuggestionContext {
                discovery_did: "did:oan:INDS:test".to_owned(),
                searchable_domains: vec!["*".to_owned()],
                max_authorized_domain_hints: 6,
                max_capability_tag_candidates: 12,
            },
        )
        .expect("discovery");
    println!("discovery tags:");
    for tag in discovery.capability_tags {
        println!("{} {}", tag.score, tag.value);
    }
}
