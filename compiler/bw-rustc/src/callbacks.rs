use std::fs;

use serde::Serialize;

use crate::config::AnalysisRequest;

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisStarted {
    pub crate_name: String,
    pub target: String,
    pub status: &'static str,
}

impl From<&AnalysisRequest> for AnalysisStarted {
    fn from(request: &AnalysisRequest) -> Self {
        Self {
            crate_name: request.crate_name.clone(),
            target: request.target.clone(),
            status: "after_analysis",
        }
    }
}

pub fn write_analysis_started(request: &AnalysisRequest) -> Result<(), std::io::Error> {
    fs::create_dir_all(&request.output_dir)?;
    let final_path = request.output_dir.join("analysis-started.json");
    let partial_path = request.output_dir.join(format!(
        "analysis-started.json.{}.partial",
        std::process::id()
    ));
    let payload = serde_json::to_vec(&AnalysisStarted::from(request))?;
    fs::write(&partial_path, payload)?;
    fs::rename(&partial_path, final_path)
}
