import pytest
from pathlib import Path
from triage import EvtxAnalyzer

def test_validate_file_not_found():
    """Test that the analyzer gracefully handles missing files."""
    analyzer = EvtxAnalyzer(Path("non_existent_file.evtx"))
    assert analyzer.validate_file() is False

def test_analyze_engine_logic(tmp_path):
    """Test the core analytic engine and export functionality."""
    # Create a dummy file
    dummy_evtx = tmp_path / "dummy.evtx"
    dummy_evtx.write_text("dummy binary data")
    
    analyzer = EvtxAnalyzer(dummy_evtx)
    assert analyzer.validate_file() is True
    
    # Run analysis
    analyzer.analyze()
    assert len(analyzer.findings) == 1
    assert analyzer.findings[0]["event_id"] == 4688
    
    # Test export
    out_file = tmp_path / "out.json"
    analyzer.export_results(out_file)
    assert out_file.exists()
    assert '"CRITICAL"' in out_file.read_text()
