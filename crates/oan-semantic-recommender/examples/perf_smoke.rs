use std::hint::black_box;
use std::time::Instant;

use oan_core::ResourceType;
use oan_semantic_recommender::{
    DiscoverySuggestionContext, DiscoverySuggestionInput, RegistrationSuggestionContext,
    RegistrationSuggestionInput, SemanticRecommender,
};

fn repeated_words(seed: &str, repeat: usize) -> String {
    (0..repeat).map(|_| seed).collect::<Vec<_>>().join(" ")
}

fn bench(name: &str, iterations: usize, mut f: impl FnMut()) {
    let started = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = started.elapsed();
    let per_call = elapsed.as_secs_f64() * 1000.0 / iterations as f64;
    let qps = iterations as f64 / elapsed.as_secs_f64();
    println!("{name}: {iterations} calls, {per_call:.3} ms/call, {qps:.0} calls/s");
}

fn main() {
    let recommender = SemanticRecommender::new().expect("recommender data");

    let long_en = repeated_words(
        "contract review legal risk clause compliance smart contract security audit openapi mcp server",
        350,
    );
    let long_zh = repeated_words(
        "合同审查 法律风险 条款分析 合规风险 智能合约 安全审计 漏洞检测 MCP 服务",
        350,
    );
    let mixed = format!("{long_zh} {long_en}");

    let registration_context = RegistrationSuggestionContext {
        registrar_did: "did:oan:INRG:perf".to_owned(),
        allowed_domains: vec!["*".to_owned()],
        max_authorized_domain_candidates: 8,
        max_capability_tag_candidates: 12,
    };
    let discovery_context = DiscoverySuggestionContext {
        discovery_did: "did:oan:INDS:perf".to_owned(),
        searchable_domains: vec!["*".to_owned()],
        max_authorized_domain_hints: 8,
        max_capability_tag_candidates: 12,
    };

    bench("registration-long-en", 100, || {
        let result = recommender
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::Skill),
                    name: "Long English resource".to_owned(),
                    description: long_en.clone(),
                    endpoint: Some("https://example.org/openapi.json".to_owned()),
                    manifest_text: Some(long_en.clone()),
                    schema_text: None,
                    locale: Some("en".to_owned()),
                },
                registration_context.clone(),
            )
            .expect("registration suggestion");
        black_box(result);
    });

    bench("registration-long-zh", 100, || {
        let result = recommender
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::Skill),
                    name: "长中文资源".to_owned(),
                    description: long_zh.clone(),
                    endpoint: None,
                    manifest_text: Some(long_zh.clone()),
                    schema_text: None,
                    locale: Some("zh".to_owned()),
                },
                registration_context.clone(),
            )
            .expect("registration suggestion");
        black_box(result);
    });

    bench("discovery-long-mixed", 100, || {
        let result = recommender
            .suggest_discovery_query(
                DiscoverySuggestionInput {
                    query: mixed.clone(),
                    current_resource_type: None,
                    current_protocol: None,
                    current_capability_tags: vec![],
                    locale: None,
                },
                discovery_context.clone(),
            )
            .expect("discovery suggestion");
        black_box(result);
    });
}
