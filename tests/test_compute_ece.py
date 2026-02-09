import numpy as np

from compute_ece import CalibrationAnalyzer


def test_ece_zero_when_all_conf_one_and_all_correct():
    conf = np.ones(10, dtype=np.float64)
    labels = np.array([0, 1] * 5, dtype=np.int64)
    preds = labels.copy()

    analyzer = CalibrationAnalyzer(n_bins=10)
    report = analyzer.compute_full_report(confidences=conf, labels=labels, predictions=preds, threshold=0.10)

    assert report.ece == 0.0
    assert report.mce == 0.0
    assert report.pass_fail == "PASS"


def test_ece_positive_when_overconfident_and_often_wrong():
    conf = np.ones(10, dtype=np.float64)
    labels = np.array([0, 1] * 5, dtype=np.int64)
    preds = np.zeros(10, dtype=np.int64)  # wrong on all "1" labels

    analyzer = CalibrationAnalyzer(n_bins=10)
    ece, bins = analyzer.compute_ece(conf, labels, preds)
    assert ece > 0.0
    assert analyzer.compute_security_ece(bins) >= ece

