use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

use oan_core::{AuthorizedDomainTaxonomy, ResourceType};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const TAXONOMY_JSON: &str = include_str!("../data/authorized_domain_taxonomy.v1.json");
const PROFILE_OVERRIDES_JSON: &str = include_str!("../data/domain_profile_overrides.json");
const CAPABILITY_TAG_TREE_JSON: &str = include_str!("../data/capability_tag_tree.v1.json");

#[derive(Debug, Error)]
pub enum RecommenderError {
    #[error("failed to load taxonomy: {0}")]
    Taxonomy(#[from] serde_json::Error),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationEvidenceKind {
    Keyword,
    Alias,
    Token,
    ResourceType,
    Protocol,
    Scope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RecommendationEvidence {
    pub kind: RecommendationEvidenceKind,
    pub term: String,
    pub matched_profile: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DomainCandidate {
    pub id: String,
    pub label: String,
    pub score: f32,
    pub covered: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<RecommendationEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ValueCandidate {
    pub value: String,
    pub score: f32,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<RecommendationEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationSuggestionInput {
    pub resource_type: Option<ResourceType>,
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationSuggestionContext {
    pub registrar_did: String,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default = "default_domain_limit")]
    pub max_authorized_domain_candidates: usize,
    #[serde(default = "default_tag_limit")]
    pub max_capability_tag_candidates: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationSuggestionResult {
    pub authorized_domains: Vec<DomainCandidate>,
    pub out_of_scope_domain_hints: Vec<DomainCandidate>,
    pub capability_tags: Vec<ValueCandidate>,
    pub resource_type_hints: Vec<ValueCandidate>,
    pub protocol_hints: Vec<ValueCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverySuggestionInput {
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_resource_type: Option<ResourceType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_protocol: Option<String>,
    #[serde(default)]
    pub current_capability_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverySuggestionContext {
    pub discovery_did: String,
    #[serde(default)]
    pub searchable_domains: Vec<String>,
    #[serde(default = "default_domain_limit")]
    pub max_authorized_domain_hints: usize,
    #[serde(default = "default_tag_limit")]
    pub max_capability_tag_candidates: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverySuggestionResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_rewrite: Option<String>,
    pub capability_tags: Vec<ValueCandidate>,
    pub resource_types: Vec<ValueCandidate>,
    pub protocols: Vec<ValueCandidate>,
    pub authorized_domain_hints: Vec<DomainCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SemanticRecommender {
    taxonomy: AuthorizedDomainTaxonomy,
    capability_tag_tree: CapabilityTagTree,
    profiles: Vec<DomainProfile>,
    tag_profiles: Vec<TagProfile>,
    tag_token_index: BTreeMap<String, Vec<usize>>,
    resource_type_rules: Vec<ValueRule>,
    protocol_rules: Vec<ValueRule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityTagTree {
    pub version: u64,
    pub snapshot_hash: Option<String>,
    #[serde(default)]
    pub tags: Vec<CapabilityTagNode>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityTagNode {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub source_count: Option<u64>,
    #[serde(default)]
    pub source_record_count: Option<u64>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub children: Vec<CapabilityTagNode>,
}

#[derive(Clone, Debug)]
struct DomainProfile {
    id: String,
    label: String,
    tokens: WeightedTerms,
    aliases: Vec<ProfilePhrase>,
    keywords: Vec<ProfilePhrase>,
}

#[derive(Clone, Debug)]
struct ProfilePhrase {
    original: String,
    normalized: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ProfileOverride {
    #[serde(default)]
    description: LocalizedText,
    #[serde(default)]
    aliases: LocalizedTerms,
    #[serde(default)]
    keywords: LocalizedTerms,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LocalizedText {
    #[serde(default)]
    en: String,
    #[serde(default)]
    zh: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LocalizedTerms {
    #[serde(default)]
    en: Vec<String>,
    #[serde(default)]
    zh: Vec<String>,
}

#[derive(Clone, Debug)]
struct WeightedTerms {
    terms: BTreeMap<String, f32>,
    total_weight: f32,
}

#[derive(Clone, Debug)]
struct TextFeatures {
    normalized: String,
    terms: WeightedTerms,
    locale: LocaleHint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocaleHint {
    En,
    Zh,
    Mixed,
}

#[derive(Clone, Debug)]
struct ScoredDomain {
    candidate: DomainCandidate,
    raw_score: f32,
}

#[derive(Clone, Debug)]
struct TagProfile {
    value: String,
    label: String,
    terms: WeightedTerms,
    phrases: Vec<ProfilePhrase>,
}

#[derive(Clone, Debug)]
struct ValueRule {
    value: &'static str,
    terms: &'static [&'static str],
    zh_terms: &'static [&'static str],
}

fn default_domain_limit() -> usize {
    6
}

fn default_tag_limit() -> usize {
    12
}

impl Default for SemanticRecommender {
    fn default() -> Self {
        Self::new().expect("embedded recommender data must be valid")
    }
}

impl SemanticRecommender {
    pub fn new() -> Result<Self, RecommenderError> {
        let mut taxonomy: AuthorizedDomainTaxonomy = serde_json::from_str(TAXONOMY_JSON)?;
        taxonomy.flatten_tree();
        let overrides: HashMap<String, ProfileOverride> =
            serde_json::from_str(PROFILE_OVERRIDES_JSON)?;
        let profiles = build_profiles(&taxonomy, &overrides);
        let capability_tag_tree: CapabilityTagTree =
            serde_json::from_str(CAPABILITY_TAG_TREE_JSON)?;
        let tag_profiles = build_tag_profiles(&capability_tag_tree);
        let tag_token_index = build_tag_token_index(&tag_profiles);
        Ok(Self {
            taxonomy,
            capability_tag_tree,
            profiles,
            tag_profiles,
            tag_token_index,
            resource_type_rules: resource_type_rules(),
            protocol_rules: protocol_rules(),
        })
    }

    pub fn taxonomy(&self) -> &AuthorizedDomainTaxonomy {
        &self.taxonomy
    }

    pub fn capability_tag_tree(&self) -> &CapabilityTagTree {
        &self.capability_tag_tree
    }

    pub fn suggest_registration_metadata(
        &self,
        input: RegistrationSuggestionInput,
        context: RegistrationSuggestionContext,
    ) -> Result<RegistrationSuggestionResult, RecommenderError> {
        let text = registration_text(&input)?;
        let features = extract_features(&text, input.locale.as_deref());
        let all_domains = self.rank_domains(&features);
        let (allowed, scope_warnings) = normalize_scope(&self.taxonomy, &context.allowed_domains);
        let (authorized_domains, out_of_scope_domain_hints) = split_registration_domains(
            &self.taxonomy,
            all_domains,
            &allowed,
            context.max_authorized_domain_candidates,
        );
        let capability_tags =
            self.rank_tag_profiles(&features, context.max_capability_tag_candidates);
        let resource_type_hints = self.rank_resource_types(&features, input.resource_type.as_ref());
        let protocol_hints = self.rank_value_rules(&features, &self.protocol_rules, 4);
        Ok(RegistrationSuggestionResult {
            authorized_domains,
            out_of_scope_domain_hints,
            capability_tags,
            resource_type_hints,
            protocol_hints,
            warnings: scope_warnings,
        })
    }

    pub fn suggest_discovery_query(
        &self,
        input: DiscoverySuggestionInput,
        context: DiscoverySuggestionContext,
    ) -> Result<DiscoverySuggestionResult, RecommenderError> {
        let query = input.query.trim();
        if query.chars().count() < 3 {
            return Err(RecommenderError::InvalidRequest(
                "query must contain at least three characters".to_owned(),
            ));
        }
        let features = extract_features(query, input.locale.as_deref());
        let (scope, scope_warnings) = normalize_scope(&self.taxonomy, &context.searchable_domains);
        let authorized_domain_hints = self
            .rank_domains(&features)
            .into_iter()
            .filter_map(|mut scored| {
                let covered = domain_covered_by_scope(&self.taxonomy, &scored.candidate.id, &scope);
                scored.candidate.covered = covered;
                if covered {
                    Some(scored.candidate)
                } else {
                    None
                }
            })
            .take(context.max_authorized_domain_hints)
            .collect();
        let capability_tags =
            self.rank_tag_profiles(&features, context.max_capability_tag_candidates);
        let resource_types =
            self.rank_resource_types(&features, input.current_resource_type.as_ref());
        let protocols = self.rank_value_rules(&features, &self.protocol_rules, 4);
        Ok(DiscoverySuggestionResult {
            query_rewrite: None,
            capability_tags,
            resource_types,
            protocols,
            authorized_domain_hints,
            warnings: scope_warnings,
        })
    }

    fn rank_domains(&self, features: &TextFeatures) -> Vec<ScoredDomain> {
        let mut scored = self
            .profiles
            .iter()
            .filter_map(|profile| {
                let (score, evidence) = score_profile(features, profile);
                if score < 0.05 {
                    return None;
                }
                let reason = explain_domain(profile, features.locale, &evidence);
                Some(ScoredDomain {
                    raw_score: score,
                    candidate: DomainCandidate {
                        id: profile.id.clone(),
                        label: profile.label.clone(),
                        score: round_score(score),
                        covered: false,
                        reason,
                        evidence,
                    },
                })
            })
            .collect::<Vec<_>>();
        scored.sort_by(|a, b| {
            b.raw_score
                .total_cmp(&a.raw_score)
                .then_with(|| a.candidate.id.cmp(&b.candidate.id))
        });
        suppress_parent_domains(scored)
    }

    fn rank_value_rules<T: RuleLike>(
        &self,
        features: &TextFeatures,
        rules: &[T],
        limit: usize,
    ) -> Vec<ValueCandidate> {
        let mut candidates = rules
            .iter()
            .filter_map(|rule| score_value_rule(features, rule))
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.value.cmp(&b.value))
        });
        candidates.truncate(limit);
        candidates
    }

    fn rank_resource_types(
        &self,
        features: &TextFeatures,
        current: Option<&ResourceType>,
    ) -> Vec<ValueCandidate> {
        let mut ranked = self.rank_value_rules(
            features,
            &self.resource_type_rules,
            self.resource_type_rules.len(),
        );
        if let Some(current) = current {
            let value = current.as_str();
            if !ranked.iter().any(|item| item.value == value) {
                ranked.push(ValueCandidate {
                    value: value.to_owned(),
                    score: 0.45,
                    reason: "Kept from the current resource type selection.".to_owned(),
                    evidence: vec![RecommendationEvidence {
                        kind: RecommendationEvidenceKind::ResourceType,
                        term: value.to_owned(),
                        matched_profile: value.to_owned(),
                    }],
                });
            }
        }
        ranked.truncate(4);
        ranked
    }

    fn rank_tag_profiles(&self, features: &TextFeatures, limit: usize) -> Vec<ValueCandidate> {
        let candidate_indexes = self.candidate_tag_profile_indexes(features);
        let mut candidates = candidate_indexes
            .into_iter()
            .filter_map(|index| score_tag_profile(features, &self.tag_profiles[index]))
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.value.cmp(&b.value))
        });
        candidates.truncate(limit);
        candidates
    }

    fn candidate_tag_profile_indexes(&self, features: &TextFeatures) -> Vec<usize> {
        let mut indexes = BTreeSet::new();
        for term in features.terms.terms.keys() {
            if let Some(candidates) = self.tag_token_index.get(term) {
                indexes.extend(candidates.iter().copied());
            }
        }
        indexes.into_iter().collect()
    }
}

pub fn normalize_capability_tags(tags: &[String]) -> Vec<String> {
    let mut normalized = tags
        .iter()
        .filter_map(|tag| {
            let value = normalize_text(tag).replace(' ', "-");
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}

trait RuleLike {
    fn value(&self) -> &'static str;
    fn terms(&self) -> &'static [&'static str];
    fn zh_terms(&self) -> &'static [&'static str];
}

impl RuleLike for ValueRule {
    fn value(&self) -> &'static str {
        self.value
    }

    fn terms(&self) -> &'static [&'static str] {
        self.terms
    }

    fn zh_terms(&self) -> &'static [&'static str] {
        self.zh_terms
    }
}

fn build_profiles(
    taxonomy: &AuthorizedDomainTaxonomy,
    overrides: &HashMap<String, ProfileOverride>,
) -> Vec<DomainProfile> {
    taxonomy
        .domains
        .iter()
        .map(|domain| {
            let override_profile = overrides.get(&domain.id);
            let mut text_parts = vec![domain.id.replace(['_', '.'], " "), domain.label.clone()];
            let mut aliases = domain.aliases.clone();
            let mut keywords = vec![domain.label.clone(), domain.id.replace(['_', '.'], " ")];
            if let Some(profile) = override_profile {
                text_parts.push(profile.description.en.clone());
                text_parts.push(profile.description.zh.clone());
                aliases.extend(profile.aliases.en.clone());
                aliases.extend(profile.aliases.zh.clone());
                keywords.extend(profile.keywords.en.clone());
                keywords.extend(profile.keywords.zh.clone());
            }
            text_parts.extend(aliases.clone());
            text_parts.extend(keywords.clone());
            DomainProfile {
                id: domain.id.clone(),
                label: domain.label.clone(),
                tokens: weighted_terms(&text_parts.join(" "), 1.0),
                aliases: build_profile_phrases(aliases),
                keywords: build_profile_phrases(keywords),
            }
        })
        .collect()
}

fn build_profile_phrases(phrases: Vec<String>) -> Vec<ProfilePhrase> {
    phrases
        .into_iter()
        .filter_map(|original| {
            let normalized = normalize_text(&original);
            if normalized.is_empty() {
                None
            } else {
                Some(ProfilePhrase {
                    original,
                    normalized,
                })
            }
        })
        .collect()
}

fn build_tag_profiles(tree: &CapabilityTagTree) -> Vec<TagProfile> {
    let mut profiles = Vec::new();
    for node in &tree.tags {
        push_tag_profile(node, &[], &mut profiles);
    }
    profiles
}

fn push_tag_profile(
    node: &CapabilityTagNode,
    parent_labels: &[String],
    profiles: &mut Vec<TagProfile>,
) {
    let mut text_parts = vec![node.id.replace(['-', '.'], " "), node.label.clone()];
    text_parts.extend(node.aliases.clone());
    text_parts.extend(parent_labels.iter().cloned());
    let mut phrase_labels = vec![node.label.clone(), node.id.replace(['-', '.'], " ")];
    phrase_labels.extend(node.aliases.clone());
    let profile = TagProfile {
        value: node.id.clone(),
        label: node.label.clone(),
        terms: weighted_terms(&text_parts.join(" "), 1.0),
        phrases: build_profile_phrases(phrase_labels),
    };
    profiles.push(profile);

    let mut next_parent_labels = parent_labels.to_vec();
    next_parent_labels.push(node.label.clone());
    for child in &node.children {
        push_tag_profile(child, &next_parent_labels, profiles);
    }
}

fn build_tag_token_index(profiles: &[TagProfile]) -> BTreeMap<String, Vec<usize>> {
    let mut index: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (profile_index, profile) in profiles.iter().enumerate() {
        for term in profile.terms.terms.keys() {
            if useful_tag_index_term(term) {
                index.entry(term.clone()).or_default().push(profile_index);
            }
        }
    }
    index
}

fn useful_tag_index_term(term: &str) -> bool {
    term.chars().count() >= 3
}

fn registration_text(input: &RegistrationSuggestionInput) -> Result<String, RecommenderError> {
    if input.name.trim().is_empty() && input.description.trim().is_empty() {
        return Err(RecommenderError::InvalidRequest(
            "name or description is required".to_owned(),
        ));
    }
    let mut parts = vec![input.name.as_str(), input.description.as_str()];
    if let Some(endpoint) = input.endpoint.as_deref() {
        parts.push(endpoint);
    }
    if let Some(manifest_text) = input.manifest_text.as_deref() {
        parts.push(manifest_text);
    }
    if let Some(schema_text) = input.schema_text.as_deref() {
        parts.push(schema_text);
    }
    Ok(parts.join(" "))
}

fn extract_features(text: &str, locale: Option<&str>) -> TextFeatures {
    let normalized = normalize_text(text);
    let locale = locale
        .and_then(parse_locale)
        .unwrap_or_else(|| detect_locale(&normalized));
    TextFeatures {
        terms: weighted_terms(&normalized, 1.0),
        normalized,
        locale,
    }
}

fn normalize_text(text: &str) -> String {
    static URL_RE: OnceLock<Regex> = OnceLock::new();
    let url_re = URL_RE.get_or_init(|| Regex::new(r"https?://[^\s]+").expect("valid url regex"));
    let text = url_re.replace_all(text, " ");
    text.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || is_cjk(ch) {
                ch.to_lowercase().next().unwrap_or(ch)
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_locale(value: &str) -> Option<LocaleHint> {
    match value.to_ascii_lowercase().as_str() {
        "zh" | "zh-cn" | "zh_hans" | "cn" => Some(LocaleHint::Zh),
        "en" | "en-us" | "en-gb" => Some(LocaleHint::En),
        "mixed" => Some(LocaleHint::Mixed),
        _ => None,
    }
}

fn detect_locale(text: &str) -> LocaleHint {
    let cjk = text.chars().filter(|ch| is_cjk(*ch)).count();
    let ascii = text.chars().filter(|ch| ch.is_ascii_alphabetic()).count();
    if cjk > 0 && ascii > 0 {
        LocaleHint::Mixed
    } else if cjk > 0 {
        LocaleHint::Zh
    } else {
        LocaleHint::En
    }
}

fn is_cjk(ch: char) -> bool {
    ('\u{4E00}'..='\u{9FFF}').contains(&ch)
        || ('\u{3400}'..='\u{4DBF}').contains(&ch)
        || ('\u{F900}'..='\u{FAFF}').contains(&ch)
}

fn weighted_terms(text: &str, base_weight: f32) -> WeightedTerms {
    let normalized = normalize_text(text);
    let mut terms: BTreeMap<String, f32> = BTreeMap::new();
    for token in normalized.split_whitespace() {
        if token.chars().any(is_cjk) {
            add_cjk_terms(token, base_weight, &mut terms);
        } else {
            add_ascii_terms(token, base_weight, &mut terms);
        }
    }
    let total_weight = terms.values().sum();
    WeightedTerms {
        terms,
        total_weight,
    }
}

fn add_ascii_terms(token: &str, weight: f32, terms: &mut BTreeMap<String, f32>) {
    if token.len() < 2 {
        return;
    }
    *terms.entry(token.to_owned()).or_default() += weight;
    let canonical = token.trim_end_matches('s');
    if canonical.len() >= 3 && canonical != token {
        *terms.entry(canonical.to_owned()).or_default() += weight * 0.75;
    }
}

fn add_cjk_terms(token: &str, weight: f32, terms: &mut BTreeMap<String, f32>) {
    let chars = token.chars().collect::<Vec<_>>();
    for n in 1..=4 {
        if chars.len() < n {
            continue;
        }
        let n_weight = match n {
            1 => weight * 0.2,
            2 => weight * 0.9,
            3 => weight,
            _ => weight * 0.85,
        };
        for window in chars.windows(n) {
            let term = window.iter().collect::<String>();
            *terms.entry(term).or_default() += n_weight;
        }
    }
}

fn score_profile(
    features: &TextFeatures,
    profile: &DomainProfile,
) -> (f32, Vec<RecommendationEvidence>) {
    let mut evidence = Vec::new();
    let token_score = weighted_jaccard(&features.terms, &profile.tokens);
    let alias_score = phrase_score(
        &features.normalized,
        &profile.aliases,
        RecommendationEvidenceKind::Alias,
        &profile.id,
        &mut evidence,
    );
    let keyword_score = phrase_score(
        &features.normalized,
        &profile.keywords,
        RecommendationEvidenceKind::Keyword,
        &profile.id,
        &mut evidence,
    );
    for term in top_overlapping_terms(&features.terms.terms, &profile.tokens.terms, 4) {
        evidence.push(RecommendationEvidence {
            kind: RecommendationEvidenceKind::Token,
            term,
            matched_profile: profile.id.clone(),
        });
    }
    let score = 0.42 * token_score + 0.31 * alias_score + 0.27 * keyword_score;
    (score.min(1.0), evidence)
}

fn weighted_jaccard(left: &WeightedTerms, right: &WeightedTerms) -> f32 {
    if left.terms.is_empty() && right.terms.is_empty() {
        return 0.0;
    }
    let (small, large) = if left.terms.len() <= right.terms.len() {
        (&left.terms, &right.terms)
    } else {
        (&right.terms, &left.terms)
    };
    let intersection = small.iter().fold(0.0, |acc, (key, small_weight)| {
        acc + large
            .get(key)
            .map(|large_weight| small_weight.min(*large_weight))
            .unwrap_or_default()
    });
    let union = left.total_weight + right.total_weight - intersection;
    if union == 0.0 {
        0.0
    } else {
        (intersection / union).min(1.0)
    }
}

fn phrase_score(
    text: &str,
    phrases: &[ProfilePhrase],
    kind: RecommendationEvidenceKind,
    profile: &str,
    evidence: &mut Vec<RecommendationEvidence>,
) -> f32 {
    let mut score: f32 = 0.0;
    for phrase in phrases {
        if text.contains(&phrase.normalized) {
            let boost = if phrase.normalized.chars().any(is_cjk) {
                0.32
            } else {
                0.26
            };
            score = score.max(boost + (phrase.normalized.chars().count() as f32 / 80.0).min(0.34));
            evidence.push(RecommendationEvidence {
                kind: kind.clone(),
                term: phrase.original.clone(),
                matched_profile: profile.to_owned(),
            });
        }
    }
    score.min(1.0)
}

fn top_overlapping_terms(
    left: &BTreeMap<String, f32>,
    right: &BTreeMap<String, f32>,
    limit: usize,
) -> Vec<String> {
    let mut scored = left
        .iter()
        .filter_map(|(term, left_weight)| {
            right.get(term).map(|right_weight| {
                (
                    term.clone(),
                    left_weight.min(*right_weight) * term.chars().count() as f32,
                )
            })
        })
        .collect::<Vec<_>>();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    scored.into_iter().map(|item| item.0).take(limit).collect()
}

fn suppress_parent_domains(scored: Vec<ScoredDomain>) -> Vec<ScoredDomain> {
    let child_ids = scored
        .iter()
        .filter_map(|item| {
            item.candidate
                .id
                .split_once('.')
                .map(|(parent, _)| parent.to_owned())
        })
        .collect::<BTreeSet<_>>();
    scored
        .into_iter()
        .filter(|item| {
            item.candidate.id.contains('.')
                || item.raw_score >= 0.65
                || !child_ids.contains(&item.candidate.id)
        })
        .collect()
}

fn explain_domain(
    profile: &DomainProfile,
    locale: LocaleHint,
    evidence: &[RecommendationEvidence],
) -> String {
    let terms = evidence
        .iter()
        .take(3)
        .map(|item| item.term.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    match locale {
        LocaleHint::Zh => {
            if terms.is_empty() {
                format!("输入内容与 {} 授权域的语义特征相近。", profile.id)
            } else {
                format!("输入内容匹配 {} 的关键词或别名：{}。", profile.id, terms)
            }
        }
        _ => {
            if terms.is_empty() {
                format!("The input is semantically close to {}.", profile.id)
            } else {
                format!("The input matches {} signals: {}.", profile.id, terms)
            }
        }
    }
}

fn normalize_scope(
    taxonomy: &AuthorizedDomainTaxonomy,
    scope: &[String],
) -> (Vec<String>, Vec<String>) {
    if scope.iter().any(|domain| domain == "*") {
        if scope.len() > 1 {
            return (
                vec!["*".to_owned()],
                vec![
                    "scope contains wildcard and concrete domains; wildcard takes precedence"
                        .to_owned(),
                ],
            );
        }
        return (vec!["*".to_owned()], vec![]);
    }
    let mut normalized = Vec::new();
    let mut warnings = Vec::new();
    for domain in scope {
        match taxonomy.normalize_domain(domain) {
            Some(canonical) => normalized.push(canonical.to_owned()),
            None => warnings.push(format!("ignored unknown authorized domain scope: {domain}")),
        }
    }
    normalized.sort();
    normalized.dedup();
    (normalized, warnings)
}

fn split_registration_domains(
    taxonomy: &AuthorizedDomainTaxonomy,
    all_domains: Vec<ScoredDomain>,
    allowed: &[String],
    limit: usize,
) -> (Vec<DomainCandidate>, Vec<DomainCandidate>) {
    let mut selectable = Vec::new();
    let mut out_of_scope = Vec::new();
    for mut scored in all_domains {
        let covered = domain_covered_by_scope(taxonomy, &scored.candidate.id, allowed);
        scored.candidate.covered = covered;
        if covered {
            if selectable.len() < limit {
                selectable.push(scored.candidate);
            }
        } else if out_of_scope.len() < 4 {
            let mut candidate = scored.candidate;
            candidate.covered = false;
            out_of_scope.push(candidate);
        }
    }
    (selectable, out_of_scope)
}

fn domain_covered_by_scope(
    taxonomy: &AuthorizedDomainTaxonomy,
    domain: &str,
    scope: &[String],
) -> bool {
    if scope.iter().any(|item| item == "*") {
        return true;
    }
    taxonomy.covers_authorized_domains(&[domain.to_owned()], scope)
}

fn score_value_rule<T: RuleLike>(features: &TextFeatures, rule: &T) -> Option<ValueCandidate> {
    let mut evidence = Vec::new();
    let mut score: f32 = 0.0;
    for term in rule.terms().iter().chain(rule.zh_terms()) {
        let normalized = normalize_text(term);
        if !normalized.is_empty() && features.normalized.contains(&normalized) {
            score = score.max(0.72 + (normalized.chars().count() as f32 / 100.0).min(0.18));
            evidence.push(RecommendationEvidence {
                kind: RecommendationEvidenceKind::Keyword,
                term: (*term).to_owned(),
                matched_profile: rule.value().to_owned(),
            });
        } else {
            let term_features = weighted_terms(term, 1.0);
            let similarity = weighted_jaccard(&features.terms, &term_features);
            if similarity > 0.08 {
                score = score.max(0.35 + similarity);
            }
        }
    }
    if score < 0.35 {
        return None;
    }
    Some(ValueCandidate {
        value: rule.value().to_owned(),
        score: round_score(score.min(1.0)),
        reason: explain_value(rule.value(), features.locale, &evidence),
        evidence,
    })
}

fn score_tag_profile(features: &TextFeatures, profile: &TagProfile) -> Option<ValueCandidate> {
    let mut evidence = Vec::new();
    let token_score = weighted_jaccard(&features.terms, &profile.terms);
    let phrase_score = tag_phrase_score(features, profile, &mut evidence);
    for term in top_overlapping_terms(&features.terms.terms, &profile.terms.terms, 3) {
        evidence.push(RecommendationEvidence {
            kind: RecommendationEvidenceKind::Token,
            term,
            matched_profile: profile.value.clone(),
        });
    }
    let score = (0.48 * phrase_score + 0.52 * token_score).min(1.0);
    if score < 0.08 {
        return None;
    }
    Some(ValueCandidate {
        value: profile.value.clone(),
        score: round_score(score),
        reason: explain_value(&profile.label, features.locale, &evidence),
        evidence,
    })
}

fn tag_phrase_score(
    features: &TextFeatures,
    profile: &TagProfile,
    evidence: &mut Vec<RecommendationEvidence>,
) -> f32 {
    let mut score: f32 = 0.0;
    for phrase in &profile.phrases {
        if phrase.normalized.is_empty() {
            continue;
        }
        if features.normalized.contains(&phrase.normalized) {
            score = score.max(0.65 + (phrase.normalized.chars().count() as f32 / 100.0).min(0.25));
            evidence.push(RecommendationEvidence {
                kind: RecommendationEvidenceKind::Keyword,
                term: phrase.original.clone(),
                matched_profile: profile.value.clone(),
            });
        }
    }
    score.min(1.0)
}

fn explain_value(value: &str, locale: LocaleHint, evidence: &[RecommendationEvidence]) -> String {
    let terms = evidence
        .iter()
        .take(3)
        .map(|item| item.term.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    match locale {
        LocaleHint::Zh => {
            if terms.is_empty() {
                format!("输入内容与 {} 相关。", value)
            } else {
                format!("输入内容包含与 {} 相关的信号：{}。", value, terms)
            }
        }
        _ => {
            if terms.is_empty() {
                format!("The input is related to {}.", value)
            } else {
                format!("The input contains {} signals: {}.", value, terms)
            }
        }
    }
}

fn round_score(value: f32) -> f32 {
    (value * 1000.0).round() / 1000.0
}

#[cfg(any())]
fn tag_rules() -> Vec<TagRule> {
    vec![
        TagRule {
            value: "contract-review",
            terms: &[
                "contract review",
                "agreement review",
                "clause analysis",
                "contract risk",
            ],
            zh_terms: &["合同审查", "合同审核", "条款分析", "合同风险", "协议审查"],
        },
        TagRule {
            value: "legal-risk-analysis",
            terms: &["legal risk", "compliance risk", "breach risk"],
            zh_terms: &["法律风险", "合规风险", "违约风险"],
        },
        TagRule {
            value: "security-audit",
            terms: &[
                "security audit",
                "vulnerability detection",
                "penetration testing",
            ],
            zh_terms: &["安全审计", "漏洞检测", "渗透测试"],
        },
        TagRule {
            value: "smart-contract-analysis",
            terms: &["smart contract", "blockchain audit", "on-chain security"],
            zh_terms: &["智能合约", "区块链审计", "链上安全"],
        },
        TagRule {
            value: "fraud-detection",
            terms: &["fraud detection", "scam detection", "transaction risk"],
            zh_terms: &["欺诈检测", "诈骗识别", "交易风险"],
        },
        TagRule {
            value: "privacy-review",
            terms: &["privacy review", "personal data", "sensitive data"],
            zh_terms: &["隐私审查", "个人信息", "敏感数据"],
        },
        TagRule {
            value: "medical-diagnosis-assistance",
            terms: &[
                "medical diagnosis",
                "clinical diagnosis",
                "diagnosis assistance",
            ],
            zh_terms: &["医疗诊断", "临床诊断", "诊断辅助"],
        },
        TagRule {
            value: "financial-analysis",
            terms: &[
                "financial analysis",
                "finance analysis",
                "accounting analysis",
            ],
            zh_terms: &["金融分析", "财务分析", "会计分析"],
        },
        TagRule {
            value: "code-review",
            terms: &["code review", "software review", "repository review"],
            zh_terms: &["代码审查", "软件审查", "仓库审查"],
        },
        TagRule {
            value: "mcp-server",
            terms: &["mcp server", "model context protocol"],
            zh_terms: &["mcp服务器", "mcp server"],
        },
    ]
}

fn resource_type_rules() -> Vec<ValueRule> {
    vec![
        ValueRule {
            value: "skill",
            terms: &["skill", "capability", "reusable skill", "agent skill"],
            zh_terms: &["技能", "能力", "可复用技能"],
        },
        ValueRule {
            value: "mcp_server",
            terms: &["mcp server", "model context protocol", "mcp tool"],
            zh_terms: &["mcp服务器", "mcp server", "模型上下文协议"],
        },
        ValueRule {
            value: "agent_service",
            terms: &["agent service", "service agent", "callable agent"],
            zh_terms: &["智能体服务", "服务智能体", "可调用智能体"],
        },
        ValueRule {
            value: "tool_api",
            terms: &["api", "tool api", "openapi", "rest api", "http api"],
            zh_terms: &["接口", "api", "工具接口"],
        },
    ]
}

fn protocol_rules() -> Vec<ValueRule> {
    vec![
        ValueRule {
            value: "mcp",
            terms: &["mcp", "mcp server", "model context protocol"],
            zh_terms: &["mcp", "模型上下文协议"],
        },
        ValueRule {
            value: "https",
            terms: &["https", "http api", "rest api", "web api", "openapi"],
            zh_terms: &["https", "http接口", "rest接口", "openapi"],
        },
        ValueRule {
            value: "a2a",
            terms: &["a2a", "agent to agent", "agent communication"],
            zh_terms: &["智能体通信", "智能体到智能体"],
        },
        ValueRule {
            value: "grpc",
            terms: &["grpc", "rpc service"],
            zh_terms: &["grpc", "rpc服务"],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recommender() -> SemanticRecommender {
        SemanticRecommender::new().unwrap()
    }

    fn registration_context(allowed_domains: Vec<&str>) -> RegistrationSuggestionContext {
        RegistrationSuggestionContext {
            registrar_did: "did:oan:INRG:test".to_owned(),
            allowed_domains: allowed_domains.into_iter().map(ToOwned::to_owned).collect(),
            max_authorized_domain_candidates: 6,
            max_capability_tag_candidates: 8,
        }
    }

    #[test]
    fn english_contract_registration_recommends_legal_contract_law() {
        let result = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::Skill),
                    name: "Contract Risk Review Skill".to_owned(),
                    description:
                        "Review supplier contracts, analyze clauses, and identify legal risk."
                            .to_owned(),
                    endpoint: Some("https://example.org/skill.json".to_owned()),
                    manifest_text: None,
                    schema_text: None,
                    locale: Some("en".to_owned()),
                },
                registration_context(vec!["legal"]),
            )
            .unwrap();
        assert_eq!(result.authorized_domains[0].id, "legal.contract_law");
        assert!(result
            .capability_tags
            .iter()
            .any(|tag| tag.value.starts_with("contract-law.")));
    }

    #[test]
    fn chinese_contract_registration_returns_canonical_english_domain() {
        let result = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::Skill),
                    name: "采购合同风险审查技能".to_owned(),
                    description: "帮助智能体审查采购合同，识别违约风险、付款条款风险和合规问题。"
                        .to_owned(),
                    endpoint: None,
                    manifest_text: None,
                    schema_text: None,
                    locale: Some("zh".to_owned()),
                },
                registration_context(vec!["legal"]),
            )
            .unwrap();
        assert_eq!(result.authorized_domains[0].id, "legal.contract_law");
        assert!(result.authorized_domains[0].covered);
    }

    #[test]
    fn registrar_scope_blocks_out_of_scope_registration_domain() {
        let result = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::Skill),
                    name: "Clinical diagnosis assistant".to_owned(),
                    description: "A medical AI tool for clinical diagnosis and patient triage."
                        .to_owned(),
                    endpoint: None,
                    manifest_text: None,
                    schema_text: None,
                    locale: Some("en".to_owned()),
                },
                registration_context(vec!["legal"]),
            )
            .unwrap();
        assert!(!result
            .authorized_domains
            .iter()
            .any(|domain| domain.id.starts_with("healthcare")));
        assert!(result
            .out_of_scope_domain_hints
            .iter()
            .any(|domain| domain.id == "healthcare.medical_technology" && !domain.covered));
    }

    #[test]
    fn wildcard_scope_allows_matching_domain() {
        let result = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::ToolApi),
                    name: "Clinical diagnosis API".to_owned(),
                    description: "A medical diagnosis API for clinical workflow.".to_owned(),
                    endpoint: None,
                    manifest_text: None,
                    schema_text: None,
                    locale: Some("en".to_owned()),
                },
                registration_context(vec!["*"]),
            )
            .unwrap();
        assert_eq!(
            result.authorized_domains[0].id,
            "healthcare.medical_technology"
        );
        assert!(result.authorized_domains[0].covered);
    }

    #[test]
    fn empty_scope_returns_no_selectable_registration_domains() {
        let result = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::Skill),
                    name: "Contract review".to_owned(),
                    description: "Review contracts and clauses.".to_owned(),
                    endpoint: None,
                    manifest_text: None,
                    schema_text: None,
                    locale: Some("en".to_owned()),
                },
                registration_context(vec![]),
            )
            .unwrap();
        assert!(result.authorized_domains.is_empty());
        assert!(result
            .out_of_scope_domain_hints
            .iter()
            .any(|domain| domain.id == "legal.contract_law"));
    }

    #[test]
    fn discovery_query_suggests_mcp_security_metadata() {
        let result = recommender()
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
                    max_capability_tag_candidates: 8,
                },
            )
            .unwrap();
        assert!(result
            .resource_types
            .iter()
            .any(|item| item.value == "mcp_server"));
        assert!(result.protocols.iter().any(|item| item.value == "mcp"));
        assert!(result
            .capability_tags
            .iter()
            .any(|item| item.value.ends_with(".security") || item.value.ends_with(".audit")));
        assert!(result
            .authorized_domain_hints
            .iter()
            .any(|item| item.id == "technology.security"));
    }

    #[test]
    fn chinese_discovery_query_suggests_contract_review() {
        let result = recommender()
            .suggest_discovery_query(
                DiscoverySuggestionInput {
                    query: "找一个可以帮助智能体审查合同风险的技能".to_owned(),
                    current_resource_type: None,
                    current_protocol: None,
                    current_capability_tags: vec![],
                    locale: Some("zh".to_owned()),
                },
                DiscoverySuggestionContext {
                    discovery_did: "did:oan:INDS:test".to_owned(),
                    searchable_domains: vec!["legal".to_owned()],
                    max_authorized_domain_hints: 6,
                    max_capability_tag_candidates: 8,
                },
            )
            .unwrap();
        assert!(result
            .authorized_domain_hints
            .iter()
            .any(|item| item.id == "legal.contract_law"));
        assert!(result
            .resource_types
            .iter()
            .any(|item| item.value == "skill"));
        assert!(result.capability_tags.iter().all(|item| {
            item.value.contains('.')
                || item
                    .value
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '-')
        }));
    }

    #[test]
    fn mixed_input_preserves_technical_tokens() {
        let result = recommender()
            .suggest_discovery_query(
                DiscoverySuggestionInput {
                    query: "找一个 MCP server 帮我做智能合约 security audit".to_owned(),
                    current_resource_type: None,
                    current_protocol: None,
                    current_capability_tags: vec![],
                    locale: None,
                },
                DiscoverySuggestionContext {
                    discovery_did: "did:oan:INDS:test".to_owned(),
                    searchable_domains: vec!["*".to_owned()],
                    max_authorized_domain_hints: 6,
                    max_capability_tag_candidates: 8,
                },
            )
            .unwrap();
        assert!(result.protocols.iter().any(|item| item.value == "mcp"));
        assert!(result
            .capability_tags
            .iter()
            .any(|item| item.value.ends_with(".security") || item.value.ends_with(".audit")));
    }

    #[test]
    fn registration_rejects_empty_name_and_description() {
        let error = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: None,
                    name: " ".to_owned(),
                    description: "\n\t".to_owned(),
                    endpoint: None,
                    manifest_text: None,
                    schema_text: None,
                    locale: None,
                },
                registration_context(vec!["*"]),
            )
            .unwrap_err();
        assert!(matches!(error, RecommenderError::InvalidRequest(_)));
    }

    #[test]
    fn discovery_rejects_too_short_query() {
        let error = recommender()
            .suggest_discovery_query(
                DiscoverySuggestionInput {
                    query: "AI".to_owned(),
                    current_resource_type: None,
                    current_protocol: None,
                    current_capability_tags: vec![],
                    locale: Some("en".to_owned()),
                },
                DiscoverySuggestionContext {
                    discovery_did: "did:oan:INDS:test".to_owned(),
                    searchable_domains: vec!["*".to_owned()],
                    max_authorized_domain_hints: 6,
                    max_capability_tag_candidates: 8,
                },
            )
            .unwrap_err();
        assert!(matches!(error, RecommenderError::InvalidRequest(_)));
    }

    #[test]
    fn invalid_scope_entries_are_warned_and_ignored() {
        let result = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::Skill),
                    name: "Contract review".to_owned(),
                    description: "Review legal contracts and clauses.".to_owned(),
                    endpoint: None,
                    manifest_text: None,
                    schema_text: None,
                    locale: Some("en".to_owned()),
                },
                registration_context(vec!["not_a_domain", "legal"]),
            )
            .unwrap();
        assert!(result
            .authorized_domains
            .iter()
            .any(|domain| domain.id == "legal.contract_law"));
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("not_a_domain")));
    }

    #[test]
    fn wildcard_mixed_scope_emits_warning() {
        let result = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::ToolApi),
                    name: "Clinical diagnosis API".to_owned(),
                    description: "A medical diagnosis API for clinical workflow.".to_owned(),
                    endpoint: None,
                    manifest_text: None,
                    schema_text: None,
                    locale: Some("en".to_owned()),
                },
                registration_context(vec!["*", "legal"]),
            )
            .unwrap();
        assert!(result
            .authorized_domains
            .iter()
            .any(|domain| domain.id == "healthcare.medical_technology"));
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("wildcard")));
    }

    #[test]
    fn zero_registration_domain_limit_still_returns_out_of_scope_hints() {
        let mut context = registration_context(vec!["legal"]);
        context.max_authorized_domain_candidates = 0;
        let result = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::Skill),
                    name: "Clinical diagnosis assistant".to_owned(),
                    description: "A medical AI tool for clinical diagnosis and patient triage."
                        .to_owned(),
                    endpoint: None,
                    manifest_text: None,
                    schema_text: None,
                    locale: Some("en".to_owned()),
                },
                context,
            )
            .unwrap();
        assert!(result.authorized_domains.is_empty());
        assert!(result
            .out_of_scope_domain_hints
            .iter()
            .any(|domain| domain.id == "healthcare.medical_technology"));
    }

    #[test]
    fn discovery_empty_scope_returns_no_domain_hints() {
        let result = recommender()
            .suggest_discovery_query(
                DiscoverySuggestionInput {
                    query: "Find a legal contract review skill".to_owned(),
                    current_resource_type: None,
                    current_protocol: None,
                    current_capability_tags: vec![],
                    locale: Some("en".to_owned()),
                },
                DiscoverySuggestionContext {
                    discovery_did: "did:oan:INDS:test".to_owned(),
                    searchable_domains: vec![],
                    max_authorized_domain_hints: 6,
                    max_capability_tag_candidates: 8,
                },
            )
            .unwrap();
        assert!(result.authorized_domain_hints.is_empty());
        assert!(result
            .capability_tags
            .iter()
            .any(|tag| tag.value.starts_with("contract-law.")));
    }

    #[test]
    fn candidate_limits_are_respected() {
        let mut context = registration_context(vec!["*"]);
        context.max_authorized_domain_candidates = 1;
        context.max_capability_tag_candidates = 1;
        let result = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::Skill),
                    name: "Smart contract security audit skill".to_owned(),
                    description: "Find vulnerabilities and perform blockchain security review."
                        .to_owned(),
                    endpoint: None,
                    manifest_text: None,
                    schema_text: None,
                    locale: Some("en".to_owned()),
                },
                context,
            )
            .unwrap();
        assert!(result.authorized_domains.len() <= 1);
        assert!(result.capability_tags.len() <= 1);
    }

    #[test]
    fn openapi_query_suggests_tool_api_and_https() {
        let result = recommender()
            .suggest_discovery_query(
                DiscoverySuggestionInput {
                    query: "OpenAPI REST API for accounting analysis".to_owned(),
                    current_resource_type: None,
                    current_protocol: None,
                    current_capability_tags: vec![],
                    locale: Some("en".to_owned()),
                },
                DiscoverySuggestionContext {
                    discovery_did: "did:oan:INDS:test".to_owned(),
                    searchable_domains: vec!["*".to_owned()],
                    max_authorized_domain_hints: 6,
                    max_capability_tag_candidates: 8,
                },
            )
            .unwrap();
        assert!(result
            .resource_types
            .iter()
            .any(|item| item.value == "tool_api"));
        assert!(result.protocols.iter().any(|item| item.value == "https"));
    }

    #[test]
    fn current_resource_type_is_preserved_as_hint() {
        let result = recommender()
            .suggest_discovery_query(
                DiscoverySuggestionInput {
                    query: "Find contract review support".to_owned(),
                    current_resource_type: Some(ResourceType::AgentService),
                    current_protocol: None,
                    current_capability_tags: vec![],
                    locale: Some("en".to_owned()),
                },
                DiscoverySuggestionContext {
                    discovery_did: "did:oan:INDS:test".to_owned(),
                    searchable_domains: vec!["legal".to_owned()],
                    max_authorized_domain_hints: 6,
                    max_capability_tag_candidates: 8,
                },
            )
            .unwrap();
        assert!(result
            .resource_types
            .iter()
            .any(|item| item.value == "agent_service"));
    }

    #[test]
    fn normalize_capability_tags_returns_stable_unique_values() {
        let tags = normalize_capability_tags(&[
            " Security Audit ".to_owned(),
            "security-audit".to_owned(),
            "MCP Server".to_owned(),
            "".to_owned(),
        ]);
        assert_eq!(tags, vec!["mcp-server", "security-audit"]);
    }

    #[test]
    fn serialized_registration_result_uses_camel_case_fields() {
        let result = recommender()
            .suggest_registration_metadata(
                RegistrationSuggestionInput {
                    resource_type: Some(ResourceType::Skill),
                    name: "Contract review".to_owned(),
                    description: "Review legal contracts and clauses.".to_owned(),
                    endpoint: None,
                    manifest_text: None,
                    schema_text: None,
                    locale: Some("en".to_owned()),
                },
                registration_context(vec!["legal"]),
            )
            .unwrap();
        let json = serde_json::to_value(result).unwrap();
        assert!(json.get("authorizedDomains").is_some());
        assert!(json.get("outOfScopeDomainHints").is_some());
        assert!(json.get("capabilityTags").is_some());
        assert!(json.get("resource_type_hints").is_none());
    }

    #[test]
    fn taxonomy_contains_expected_authorized_domains() {
        let recommender = recommender();
        assert!(recommender
            .taxonomy()
            .normalize_domain("legal.contract_law")
            .is_some());
        assert!(recommender
            .taxonomy()
            .normalize_domain("technology.security")
            .is_some());
        assert!(recommender
            .taxonomy()
            .covers_authorized_domains(&["legal.contract_law".to_owned()], &["legal".to_owned()]));
    }

    #[test]
    fn capability_tag_tree_loads_cleaned_agenttaxo_tags() {
        let recommender = recommender();
        let tree = recommender.capability_tag_tree();
        assert_eq!(tree.version, 1);
        assert!(tree.tags.len() >= 150);
        assert!(tree
            .snapshot_hash
            .as_deref()
            .is_some_and(|hash| hash.starts_with("sha256:")));
        assert!(tree.tags.iter().any(|node| node.id == "contract-law"
            && node
                .children
                .iter()
                .any(|child| child.id == "contract-law.force-majeure"
                    && child.source_count.is_some_and(|count| count >= 5))));
        assert!(tree
            .tags
            .iter()
            .flat_map(|node| &node.children)
            .all(|child| child.source_count.is_some_and(|count| count >= 5)));
        let cross_cutting = tree
            .tags
            .iter()
            .find(|node| node.id == "cross-cutting")
            .expect("cross-cutting parent tag");
        assert!(cross_cutting.children.iter().any(|child| {
            child.id == "cross-cutting.regulatory-compliance"
                && child.source_count.is_some_and(|count| count >= 5)
        }));
        assert!(tree
            .tags
            .iter()
            .filter(|node| node.id != "cross-cutting")
            .flat_map(|node| &node.children)
            .all(|child| child.label != "Regulatory Compliance"));
    }
}
