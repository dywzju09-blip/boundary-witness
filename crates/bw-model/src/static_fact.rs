use serde::{Deserialize, Serialize};

use crate::{
    BuildId, ModelError, RecordId, STATIC_SCHEMA_V02, SemanticSiteKey, SiteId,
    schema::{deserialize_static_schema, require_static_schema_version},
};

/// 闭包对目标对象的静态捕获方式。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    Borrowed,
    Owned,
}

/// MIR 中对象创建或进入可跟踪状态的位置。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectSiteFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub type_name: String,
}

/// MIR 中 callback/闭包实例的定义位置。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackSiteFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub def_path: String,
}

/// callback site 与被捕获 object site 之间的静态边。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackCaptureFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub callback_site_id: SiteId,
    pub object_site_id: SiteId,
    pub capture_ordinal: u32,
    pub capture_mode: CaptureMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropKind {
    Explicit,
    ScopeEnd,
}

/// 对象发生显式 drop 或作用域结束 drop 的 MIR 位置。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DropSiteFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub object_site_id: SiteId,
    pub drop_kind: DropKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropPreventionKind {
    MemForget,
}

/// 对象在 MIR 中被显式阻止自动 drop 的位置，例如 `mem::forget(owner)`。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DropPreventionFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub object_site_id: SiteId,
    pub prevention_kind: DropPreventionKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackUserDataReconstructionKind {
    OwnerFromTransmute,
    OwnerFromRaw,
    LeakFromRaw,
}

/// `extern` callback 中从 foreign `user_data` raw pointer 重建 Rust owner/view 的位置。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackUserDataReconstructionFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub callback_site_id: SiteId,
    pub user_data_site_id: SiteId,
    pub object_site_id: SiteId,
    pub reconstruction_kind: CallbackUserDataReconstructionKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationRole {
    Register,
    Unregister,
    Replace,
}

/// 被 API map 分类为 callback 注册、注销或替换的调用点。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationSiteFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub callback_site_id: Option<SiteId>,
    /// A compiler-resolved raw-pointer user-data object passed with this registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data_site_id: Option<SiteId>,
    pub api_id: String,
    pub role: RegistrationRole,
}

/// 编译器可回溯的 raw-pointer 所有权转移方向。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPointerTransferKind {
    IntoRaw,
    FromRaw,
    FromRawParts,
}

/// `Box` / `Arc` / `Rc` raw-pointer 转移与逻辑 user-data object 的静态关系。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPointerTransferFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub user_data_site_id: SiteId,
    pub transfer_kind: RawPointerTransferKind,
}

/// MIR control-flow proof that a local release endpoint is unavoidable after registration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePathProofFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub registration_site_id: SiteId,
    pub release_site_id: SiteId,
    pub object_site_id: SiteId,
}

/// callback userdata release 与后续 callback use 之间的可回查顺序结论。
///
/// 前两个变体是顺序证明。`UnknownOrdering` 不是证明而是缺证记录：register、release
/// 与 callback use 都已绑定到同一对象，但 MIR CFG 无法为 release 与 use 定序（两者
/// 互相可达的循环，或位于互不可达的分支）。该情况此前被静默丢弃，既不产生事实也不
/// 产生缺证记录，因而无法与"根本没有 use"区分。
///
/// 消费方必须把 `UnknownOrdering` 当作缺证：它不得点亮 `lifecycle_ordering` 或
/// `complete_risk_chain` 证明层，见 `lifecycle_v326` 的
/// `PROVEN_CALLBACK_RELEASE_USE_ORDER_OBJECT_IDS`。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackReleaseUseOrdering {
    ReleaseBeforeCallbackUse,
    CallbackUseBeforeRelease,
    UnknownOrdering,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackReleaseUseOrderFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub registration_site_id: SiteId,
    pub release_site_id: SiteId,
    pub use_site_id: SiteId,
    pub object_site_id: SiteId,
    pub api_id: String,
    pub ordering: CallbackReleaseUseOrdering,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalCallRole {
    Invoke,
    ExternalCall,
}

/// Rust 边界上被 API map 分类的外部调用点。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCallSiteFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub callback_site_id: Option<SiteId>,
    pub api_id: String,
    pub role: ExternalCallRole,
}

/// 一个回调泛型参数的存活期被什么约束住。
///
/// 这是**定义点**属性：只读函数签名，不需要任何调用代码。它是"安全 API 允许 UB"这类
/// 组件级缺陷的本体形状——`rusqlite` 0.26.1 的 `update_hook` 用 `F: FnMut(..) + 'c`
/// 把回调绑在 `&'c mut self` 这一次借用上，而真正持有回调的是 C 侧的 sqlite3 句柄，
/// 它不受那次借用约束；0.26.2 把 bound 收紧成 `'static` 就修好了。
///
/// 四个取值都会产出事实，包括健全的那两个。缺证与"已检查且健全"必须可区分：没有事实
/// 只说明这条签名没被分析到，不等于它安全。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackLifetimeBoundScope {
    /// bound 指向本函数声明的某个 lifetime 参数，且该 lifetime 也出现在 receiver 上。
    /// 回调的存活期被绑在一次 `&'a self` 借用上——外部持有方并不受这个借用约束。
    DeclaredReceiverLifetime,
    /// bound 指向本函数声明的某个 lifetime 参数，但该 lifetime 不来自 receiver
    /// （例如由另一个参数或返回值引入）。仍然短于 `'static`。
    DeclaredFreeLifetime,
    /// bound 是 `'static`。回调不能借用任何有限存活期的数据。
    StaticLifetime,
    /// 有 `Fn` 家族 bound 但完全没有 outlives bound。存活期由推断决定，签名本身不表态。
    NoLifetimeBound,
}

impl CallbackLifetimeBoundScope {
    /// bound 是否短于 `'static`，即签名允许回调借用有限存活期的数据。
    #[must_use]
    pub fn is_shorter_than_static(self) -> bool {
        matches!(
            self,
            Self::DeclaredReceiverLifetime | Self::DeclaredFreeLifetime
        )
    }
}

/// 回调参数在定义点上的生命周期 bound。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackLifetimeBoundFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub api_id: String,
    /// 回调那个泛型类型参数的名字，例如 `F`。
    pub callback_param: String,
    /// 约束它的 lifetime 名字，例如 `'c` 或 `'static`。
    /// [`CallbackLifetimeBoundScope::NoLifetimeBound`] 时为 `None`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_lifetime: Option<String>,
    pub bound_scope: CallbackLifetimeBoundScope,
}

/// 返回值借用关系：API 返回的引用可追溯到输入或本地 owner。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnedBorrowRelationKind {
    /// MIR/dataflow 观察到返回值直接来源于输入或本地 owner borrow。
    DirectReturnBorrow,
    /// HIR signature 观察到方法声明 lifetime 只出现在返回 view 中，未被 receiver/input 约束。
    UnconstrainedReturnLifetime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnedBorrowRelationFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub source_site_id: SiteId,
    pub returned_site_id: SiteId,
    pub api_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_kind: Option<ReturnedBorrowRelationKind>,
}

/// 返回借用视图被保存进集合、字段或 owner 状态中的静态关系。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedReturnedBorrowFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub source_site_id: SiteId,
    pub returned_site_id: SiteId,
    pub storage_site_id: SiteId,
    pub api_id: String,
}

/// 返回借用视图的保存、失效与后续使用之间的可回查顺序。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnedBorrowInvalidationOrdering {
    PersistenceBeforeInvalidationUse,
    InvalidationBeforePersistenceUse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnedBorrowInvalidationOrderFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub persisted_site_id: SiteId,
    pub invalidation_site_id: SiteId,
    pub use_site_id: SiteId,
    pub api_id: String,
    pub invalidation_api_id: String,
    pub ordering: ReturnedBorrowInvalidationOrdering,
}

/// 外部 buffer/handle 与 Rust 借用来源之间的静态绑定。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalBufferBindingFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub source_site_id: SiteId,
    pub buffer_site_id: SiteId,
    pub api_id: String,
}

/// Atomic operation observed at a lifecycle-sensitive iterator/container site.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicOperationKind {
    Load,
}

/// Memory ordering used by an observed atomic operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicOrderingKind {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst,
}

/// Atomic ordering fact for iterator/container lifecycle visibility.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicOrderingFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub api_id: String,
    pub operation: AtomicOperationKind,
    pub ordering: AtomicOrderingKind,
    pub target_type_name: String,
}

/// 同一生命周期对象在静态站点之间发生的中性流转关系。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectFlowKind {
    Argument,
    ReturnValue,
    FieldStore,
    FieldLoad,
    WrapperMove,
    WrapperDestructure,
    CollectionStore,
    CollectionLoad,
    ClosureCapture,
}

/// ObjectFlow 端点的中性对象角色。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectFlowObjectKind {
    Callback,
    UserData,
    RustOwner,
    ReturnedRef,
    Storage,
    OpaqueHandle,
    StaticSite,
}

/// 保守对象绑定缺口的中性归因。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectBindingGapKind {
    SelectionPredicate,
    MappedValue,
    MergedSources,
    TupleProjection,
    CardinalityTransform,
    DynamicIndex,
    RangeOrSlice,
    SequenceLengthUnknown,
    KeyContract,
    ReassignmentBarrier,
    MutationBarrier,
    /// 调用边界上对象绑定丢失：callee 已被证明是注册 helper 且 userdata 参数下标已知，
    /// 但调用者一侧该实参无法解析回被跟踪的对象。此前这类情况被静默丢弃，缺口在事实流
    /// 里不可见，扫描结果无法区分"没有绑定"与"没有注册"。
    CallBoundary,
    /// 连 callee 是谁都没确定：间接调用（函数指针、trait object、动态分发）且
    /// 指针来源追踪不到定义。这类调用背后可能藏着注册，也可能什么都没有——分析
    /// 无法分辨。此前直接跳过，于是"看过且没有注册"与"根本没看见"在事实流里长得
    /// 一模一样。记录下来才能把它算成覆盖缺口而不是阴性结论。
    UnresolvedCallee,
}

/// 编译器明确拒绝把某处静态观察升级为同对象绑定时的诊断事实。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectBindingGapFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub api_id: String,
    pub gap_kind: ObjectBindingGapKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_type_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
}

/// 保守 method-effect summary 产出的对象流事实。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectFlowFact {
    pub site_id: SiteId,
    pub semantic_site_key: SemanticSiteKey,
    pub from_site_id: SiteId,
    pub from_object_kind: ObjectFlowObjectKind,
    pub to_site_id: SiteId,
    pub to_object_kind: ObjectFlowObjectKind,
    pub flow_kind: ObjectFlowKind,
    pub api_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_type_name: Option<String>,
}

/// `bw.static/0.1` 支持的静态事实种类。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StaticFact {
    ObjectSite(ObjectSiteFact),
    CallbackSite(CallbackSiteFact),
    CallbackCapture(CallbackCaptureFact),
    DropSite(DropSiteFact),
    DropPrevention(DropPreventionFact),
    CallbackUserDataReconstruction(CallbackUserDataReconstructionFact),
    RegistrationSite(RegistrationSiteFact),
    RawPointerTransfer(RawPointerTransferFact),
    ReleasePathProof(ReleasePathProofFact),
    CallbackReleaseUseOrder(CallbackReleaseUseOrderFact),
    ExternalCallSite(ExternalCallSiteFact),
    CallbackLifetimeBound(CallbackLifetimeBoundFact),
    ReturnedBorrowRelation(ReturnedBorrowRelationFact),
    PersistedReturnedBorrow(PersistedReturnedBorrowFact),
    ReturnedBorrowInvalidationOrder(ReturnedBorrowInvalidationOrderFact),
    ExternalBufferBinding(ExternalBufferBindingFact),
    AtomicOrdering(AtomicOrderingFact),
    ObjectBindingGap(ObjectBindingGapFact),
    ObjectFlow(ObjectFlowFact),
}

/// 产出静态事实的编译产物身份。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticArtifactIdentity {
    pub crate_id: String,
    pub package_name: String,
    pub package_version: String,
    pub target: String,
}

/// 可回查到源码位置的静态事实锚点。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticSourceRef {
    pub path: String,
    pub line_start: u64,
    pub line_end: u64,
    pub symbol_path: Option<String>,
}

/// 每条静态事实的版本化公共信封。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticFactEnvelope {
    #[serde(deserialize_with = "deserialize_static_schema")]
    pub schema_version: String,
    pub record_id: RecordId,
    pub producer: String,
    pub build_id: BuildId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<StaticArtifactIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<StaticSourceRef>,
    pub payload: StaticFact,
}

impl StaticFactEnvelope {
    /// 解析并校验受支持的 `bw.static` 版本。
    pub fn from_json_str(input: &str) -> Result<Self, ModelError> {
        require_static_schema_version(input)?;
        Ok(serde_json::from_str(input)?)
    }

    /// 仅在完整的 `bw.static/0.2` 身份和源码锚点都存在时返回 true。
    #[must_use]
    pub fn is_authoritative_lifecycle_binding(&self) -> bool {
        self.schema_version == STATIC_SCHEMA_V02
            && has_required_text(self.record_id.as_str())
            && has_required_text(&self.producer)
            && has_required_text(self.build_id.as_str())
            && self
                .artifact
                .as_ref()
                .is_some_and(StaticArtifactIdentity::has_required_fields)
            && self
                .source_ref
                .as_ref()
                .is_some_and(StaticSourceRef::has_valid_source_span)
            && self.payload.has_required_identifiers()
    }
}

impl StaticFact {
    fn has_required_identifiers(&self) -> bool {
        match self {
            Self::ObjectSite(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(&fact.type_name)
            }
            Self::CallbackSite(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(&fact.def_path)
            }
            Self::CallbackCapture(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.callback_site_id.as_str())
                    && has_required_text(fact.object_site_id.as_str())
            }
            Self::DropSite(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.object_site_id.as_str())
            }
            Self::DropPrevention(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.object_site_id.as_str())
            }
            Self::CallbackUserDataReconstruction(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.callback_site_id.as_str())
                    && has_required_text(fact.user_data_site_id.as_str())
                    && has_required_text(fact.object_site_id.as_str())
            }
            Self::RegistrationSite(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(&fact.api_id)
                    && fact
                        .callback_site_id
                        .as_ref()
                        .is_none_or(|site_id| has_required_text(site_id.as_str()))
                    && fact
                        .user_data_site_id
                        .as_ref()
                        .is_none_or(|site_id| has_required_text(site_id.as_str()))
            }
            Self::RawPointerTransfer(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.user_data_site_id.as_str())
            }
            Self::ReleasePathProof(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.registration_site_id.as_str())
                    && has_required_text(fact.release_site_id.as_str())
                    && has_required_text(fact.object_site_id.as_str())
            }
            Self::CallbackReleaseUseOrder(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.registration_site_id.as_str())
                    && has_required_text(fact.release_site_id.as_str())
                    && has_required_text(fact.use_site_id.as_str())
                    && has_required_text(fact.object_site_id.as_str())
                    && has_required_text(&fact.api_id)
            }
            Self::ExternalCallSite(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(&fact.api_id)
                    && fact
                        .callback_site_id
                        .as_ref()
                        .is_none_or(|site_id| has_required_text(site_id.as_str()))
            }
            Self::CallbackLifetimeBound(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(&fact.api_id)
                    && has_required_text(&fact.callback_param)
                    && fact.bound_lifetime.as_deref().is_none_or(has_required_text)
            }
            Self::ReturnedBorrowRelation(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.source_site_id.as_str())
                    && has_required_text(fact.returned_site_id.as_str())
                    && has_required_text(&fact.api_id)
            }
            Self::PersistedReturnedBorrow(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.source_site_id.as_str())
                    && has_required_text(fact.returned_site_id.as_str())
                    && has_required_text(fact.storage_site_id.as_str())
                    && has_required_text(&fact.api_id)
            }
            Self::ReturnedBorrowInvalidationOrder(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.persisted_site_id.as_str())
                    && has_required_text(fact.invalidation_site_id.as_str())
                    && has_required_text(fact.use_site_id.as_str())
                    && has_required_text(&fact.api_id)
                    && has_required_text(&fact.invalidation_api_id)
            }
            Self::ExternalBufferBinding(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.source_site_id.as_str())
                    && has_required_text(fact.buffer_site_id.as_str())
                    && has_required_text(&fact.api_id)
            }
            Self::AtomicOrdering(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(&fact.api_id)
                    && has_required_text(&fact.target_type_name)
            }
            Self::ObjectBindingGap(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(&fact.api_id)
                    && fact.field_path.as_deref().is_none_or(has_required_text)
                    && fact
                        .container_type_name
                        .as_deref()
                        .is_none_or(has_required_text)
                    && fact.adapter.as_deref().is_none_or(has_required_text)
            }
            Self::ObjectFlow(fact) => {
                has_required_text(fact.site_id.as_str())
                    && has_required_text(fact.semantic_site_key.as_str())
                    && has_required_text(fact.from_site_id.as_str())
                    && has_required_text(fact.to_site_id.as_str())
                    && has_required_text(&fact.api_id)
                    && fact.field_path.as_deref().is_none_or(has_required_text)
                    && fact
                        .container_type_name
                        .as_deref()
                        .is_none_or(has_required_text)
            }
        }
    }
}

impl StaticArtifactIdentity {
    fn has_required_fields(&self) -> bool {
        has_required_text(&self.crate_id)
            && has_required_text(&self.package_name)
            && has_required_text(&self.package_version)
            && has_required_text(&self.target)
    }
}

impl StaticSourceRef {
    fn has_valid_source_span(&self) -> bool {
        has_required_text(&self.path)
            && self.line_start >= 1
            && self.line_end >= self.line_start
            && self.symbol_path.as_deref().is_none_or(has_required_text)
    }
}

fn has_required_text(value: &str) -> bool {
    !value.trim().is_empty()
}
