use std::collections::BTreeMap;

use bw_model::{
    BuildId, CallbackCaptureFact, ObjectSiteFact, RecordId, SemanticSiteKey, SiteId, StaticFact,
    StaticFactEnvelope,
};

use crate::OracleError;

/// 静态事实的确定性索引。索引只保存事实，不推导生命周期结论。
#[derive(Clone, Debug, Default)]
pub struct StaticFactIndex {
    facts: BTreeMap<RecordId, StaticFactEnvelope>,
    build_id: Option<BuildId>,
    object_sites: BTreeMap<SiteId, RecordId>,
    site_semantics: BTreeMap<SiteId, SemanticSiteKey>,
    captures: BTreeMap<(SiteId, SiteId), Vec<RecordId>>,
}

impl StaticFactIndex {
    pub fn from_envelopes(
        facts: impl IntoIterator<Item = StaticFactEnvelope>,
    ) -> Result<Self, OracleError> {
        let mut index = Self::default();
        for envelope in facts {
            if let Some(expected) = &index.build_id {
                if expected != &envelope.build_id {
                    return Err(OracleError::new(
                        "BW-ORACLE-STATIC-BUILD-MISMATCH",
                        format!(
                            "静态事实同时包含 build_id {} 和 {}",
                            expected, envelope.build_id
                        ),
                    ));
                }
            } else {
                index.build_id = Some(envelope.build_id.clone());
            }
            if index.facts.contains_key(&envelope.record_id) {
                return Err(OracleError::new(
                    "BW-ORACLE-STATIC-RECORD-DUPLICATE",
                    format!("静态 record_id {} 重复", envelope.record_id),
                ));
            }

            match &envelope.payload {
                StaticFact::ObjectSite(fact) => {
                    insert_unique_site(
                        &mut index.object_sites,
                        &fact.site_id,
                        &envelope.record_id,
                        "object",
                    )?;
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::CallbackSite(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::CallbackCapture(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                    index
                        .captures
                        .entry((fact.callback_site_id.clone(), fact.object_site_id.clone()))
                        .or_default()
                        .push(envelope.record_id.clone());
                }
                StaticFact::DropSite(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::DropPrevention(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::CallbackUserDataReconstruction(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::RegistrationSite(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::RawPointerTransfer(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::ReleasePathProof(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::CallbackReleaseUseOrder(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::ExternalCallSite(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::CallbackLifetimeBound(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::ReturnedBorrowRelation(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::PersistedReturnedBorrow(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::ReturnedBorrowInvalidationOrder(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::ExternalBufferBinding(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::AtomicOrdering(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::ObjectBindingGap(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
                StaticFact::ObjectFlow(fact) => {
                    index
                        .site_semantics
                        .insert(fact.site_id.clone(), fact.semantic_site_key.clone());
                }
            }
            index.facts.insert(envelope.record_id.clone(), envelope);
        }
        Ok(index)
    }

    #[must_use]
    pub fn build_id(&self) -> Option<&BuildId> {
        self.build_id.as_ref()
    }

    pub(crate) fn object_fact(
        &self,
        site_id: &SiteId,
    ) -> Result<(&RecordId, &ObjectSiteFact), OracleError> {
        let record_id = self.object_sites.get(site_id).ok_or_else(|| {
            OracleError::new(
                "BW-ORACLE-STATIC-OBJECT-MISSING",
                format!("缺少 object site {} 的静态事实", site_id),
            )
        })?;
        let envelope = self
            .facts
            .get(record_id)
            .expect("object site index must reference an existing fact");
        let StaticFact::ObjectSite(fact) = &envelope.payload else {
            unreachable!("object site index must reference an object fact");
        };
        Ok((record_id, fact))
    }

    pub(crate) fn capture_fact(
        &self,
        callback_site_id: &SiteId,
        object_site_id: &SiteId,
    ) -> Result<(&RecordId, &CallbackCaptureFact), OracleError> {
        let key = (callback_site_id.clone(), object_site_id.clone());
        let records = self.captures.get(&key).ok_or_else(|| {
            OracleError::new(
                "BW-ORACLE-STATIC-CAPTURE-MISSING",
                format!(
                    "缺少 callback site {} 到 object site {} 的 capture 事实",
                    callback_site_id, object_site_id
                ),
            )
        })?;
        if records.len() != 1 {
            return Err(OracleError::new(
                "BW-ORACLE-STATIC-CAPTURE-AMBIGUOUS",
                format!(
                    "callback site {} 到 object site {} 对应 {} 条 capture 事实",
                    callback_site_id,
                    object_site_id,
                    records.len()
                ),
            ));
        }
        let record_id = &records[0];
        let envelope = self
            .facts
            .get(record_id)
            .expect("capture index must reference an existing fact");
        let StaticFact::CallbackCapture(fact) = &envelope.payload else {
            unreachable!("capture index must reference a capture fact");
        };
        Ok((record_id, fact))
    }

    pub(crate) fn semantic_key(&self, site_id: &SiteId) -> Option<&SemanticSiteKey> {
        self.site_semantics.get(site_id)
    }
}

fn insert_unique_site(
    sites: &mut BTreeMap<SiteId, RecordId>,
    site_id: &SiteId,
    record_id: &RecordId,
    kind: &str,
) -> Result<(), OracleError> {
    if sites.insert(site_id.clone(), record_id.clone()).is_some() {
        return Err(OracleError::new(
            "BW-ORACLE-STATIC-SITE-DUPLICATE",
            format!("{kind} site_id {site_id} 重复"),
        ));
    }
    Ok(())
}
