# loghunter/ui/tabs/rules.py — Phase 3 #12
from __future__ import annotations
import streamlit as st

def validate_sigma_yaml(yaml_content: str) -> tuple[bool, str]:
    """Validate Sigma YAML structure. Returns (is_valid, error_message). Never raises."""
    try:
        from ruamel.yaml import YAML
        import io
        yaml = YAML()
        data = yaml.load(io.StringIO(yaml_content))
        if not isinstance(data, dict):
            return False, "YAML must be a mapping"
        if "title" not in data:
            return False, "Missing required 'title' field"
        if "detection" not in data:
            return False, "Missing required 'detection' field"
        return True, ""
    except Exception as exc:
        return False, str(exc)

def store_and_log(rule_id, yaml_content, sigma_engine) -> dict:
    """Store rule. Returns dict: success, rule_id, error. Never raises."""
    try:
        sigma_engine.store_rule(rule_id, yaml_content)
        return {"success": True, "rule_id": rule_id, "error": None}
    except Exception as exc:
        return {"success": False, "rule_id": rule_id, "error": str(exc)}

def confirm_and_log(rule_id, session_id, sigma_engine) -> dict:
    """Confirm rule. Returns dict: success, error. Never raises."""
    try:
        sigma_engine.confirm_rule(rule_id, session_id)
        return {"success": True, "error": None}
    except Exception as exc:
        return {"success": False, "error": str(exc)}

def export_and_return(rule_id, sigma_engine) -> dict:
    """Export rule YAML. Returns dict: success, yaml_content, error. Never raises."""
    try:
        yaml_content = sigma_engine.export_rule(rule_id)
        return {"success": True, "yaml_content": yaml_content, "error": None}
    except Exception as exc:
        return {"success": False, "yaml_content": None, "error": str(exc)}

def render(sigma_engine, draft_generator, builder) -> None:
    st.header("📜 Rules — Sigma Lifecycle")
    tab_browse, tab_new, tab_draft = st.tabs(["Browse Rules", "New Rule", "Generate Draft"])
    with tab_browse:
        rules = sigma_engine.list_rules()
        if rules:
            import pandas as pd
            st.dataframe(pd.DataFrame(rules)[["rule_id","version","analyst_confirmed","created_at"]])
        else:
            st.info("No rules stored yet.")
    with tab_new:
        rule_id = st.text_input("Rule ID")
        yaml_content = st.text_area("Sigma YAML", height=200)
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("Store"):
                ok, err = validate_sigma_yaml(yaml_content)
                if not ok:
                    st.error(f"Invalid YAML: {err}")
                else:
                    r = store_and_log(rule_id, yaml_content, sigma_engine)
                    st.success("Stored.") if r["success"] else st.error(r["error"])
        with col2:
            if st.button("Confirm"):
                r = confirm_and_log(rule_id, None, sigma_engine)
                st.success("Confirmed.") if r["success"] else st.error(r["error"])
        with col3:
            if st.button("Export"):
                r = export_and_return(rule_id, sigma_engine)
                if r["success"]:
                    st.download_button("Download YAML", r["yaml_content"], file_name=f"{rule_id}.yml")
                else:
                    st.error(r["error"])
    with tab_draft:
        st.info("Select an event from Investigate tab first, then generate a draft rule.")
        if st.button("Generate Draft"):
            st.warning("No event selected.")