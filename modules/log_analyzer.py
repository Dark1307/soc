import re
import pickle
import os
from datetime import datetime
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from modules.dataset import DATASET, LABEL_NAMES, SEVERITY_MAP

# ─── Model file path ───
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ml_model.pkl')

def train_model():
    """Train Random Forest model on dataset and save it."""
    print('[ML] Training model on dataset...')

    texts  = [d[0] for d in DATASET]
    labels = [d[1] for d in DATASET]

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(2, 4),
            max_features=5000,
            lowercase=True,
            sublinear_tf=True,
        )),
        ('clf', RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            class_weight='balanced',
        ))
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42
    )

    pipeline.fit(X_train, y_train)

    y_pred   = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print('[ML] Model trained! Accuracy: {:.1f}%'.format(accuracy * 100))

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(pipeline, f)

    print('[ML] Model saved to: ' + MODEL_PATH)
    return pipeline, accuracy

def load_model():
    """Load saved model or train new one."""
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, 'rb') as f:
                pipeline = pickle.load(f)
            print('[ML] Model loaded from disk.')
            return pipeline
        except:
            print('[ML] Failed to load model, retraining...')
            pipeline, _ = train_model()
            return pipeline
    else:
        pipeline, _ = train_model()
        return pipeline

# ─── Load model on startup ───
print('[ML] Initializing ML Log Analyzer...')
MODEL = load_model()
print('[ML] Ready!')

def extract_ip(line):
    """Extract IP address from log line."""
    match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
    return match.group(1) if match else 'Unknown'

def extract_timestamp(line):
    """Extract timestamp from log line."""
    patterns = [
        r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})',
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
    ]
    for p in patterns:
        match = re.search(p, line)
        if match:
            return match.group(1)
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def predict_line(line):
    """
    Predict attack type for a single log line
    using the trained ML model.
    Returns (label_id, label_name, confidence)
    """
    try:
        pred       = MODEL.predict([line])[0]
        proba      = MODEL.predict_proba([line])[0]
        confidence = round(float(max(proba)) * 100, 1)
        label_id   = int(pred)
        return label_id, LABEL_NAMES[label_id], confidence
    except Exception as e:
        print('[ML] Prediction error: ' + str(e))
        return 0, 'Normal', 0.0

def analyze(logs_text):
    """
    Main log analysis function using ML model.
    Each line is classified by the Random Forest model.
    """
    lines = logs_text.strip().split('\n')
    lines = [l.strip() for l in lines if l.strip()]

    total_lines   = len(lines)
    events        = []
    attack_counts = defaultdict(int)
    attacker_ips  = defaultdict(list)
    summary_logs  = []

    summary_logs.append('[ML] Starting ML-based analysis on ' +
                        str(total_lines) + ' log lines...')
    summary_logs.append('[ML] Model: Random Forest + TF-IDF Vectorizer')
    summary_logs.append('[ML] Classes: Normal, SQL Injection, XSS, ' +
                        'Path Traversal, Command Injection, DoS')

    for line in lines:
        ip        = extract_ip(line)
        timestamp = extract_timestamp(line)

        # ─── ML Prediction ───
        label_id, label_name, confidence = predict_line(line)

        # Skip normal traffic
        if label_id == 0:
            summary_logs.append('[NORMAL] ' + line[:80])
            continue

        # Attack detected
        severity = SEVERITY_MAP.get(label_id, 'MEDIUM')
        attack_counts[label_name] += 1
        attacker_ips[ip].append(label_name)

        events.append({
            'type':       label_name,
            'severity':   severity,
            'ip':         ip,
            'timestamp':  timestamp,
            'line':       line[:200],
            'confidence': float(confidence),
            'label_id':   int(label_id),
        })

        summary_logs.append(
            '[' + severity + '] ' + label_name +
            ' detected from ' + ip +
            ' (confidence: ' + str(confidence) + '%) — ' +
            line[:80]
        )

    # ─── Remove duplicates ───
    seen          = set()
    unique_events = []
    for e in events:
        key = e['ip'] + '_' + e['type'] + '_' + e['line'][:50]
        if key not in seen:
            seen.add(key)
            unique_events.append(e)

    # ─── Top attackers ───
    top_attackers = []
    for ip, attacks in attacker_ips.items():
        if ip != 'Unknown':
            top_attackers.append({
                'ip':    ip,
                'count': int(len(attacks)),
                'types': list(set(attacks))
            })
    top_attackers.sort(key=lambda x: x['count'], reverse=True)

    # ─── Risk level ───
    total_attacks = int(sum(attack_counts.values()))
    if total_attacks == 0:
        risk_level = 'LOW'
    elif total_attacks < 5:
        risk_level = 'MEDIUM'
    elif total_attacks < 15:
        risk_level = 'HIGH'
    else:
        risk_level = 'CRITICAL'

    # ─── Add all attack types to counts (even 0) ───
    all_types = [
        'SQL Injection', 'XSS', 'Path Traversal',
        'Command Injection', 'DoS'
    ]
    for t in all_types:
        if t not in attack_counts:
            attack_counts[t] = 0

    summary_logs.append('[DONE] ML Analysis complete.')
    summary_logs.append('[SUMMARY] Attacks detected: ' + str(total_attacks))
    summary_logs.append('[RISK] Risk level: ' + risk_level)

    return {
        'total_lines':   int(total_lines),
        'total_attacks': int(total_attacks),
        'risk_level':    risk_level,
        'attack_counts': {k: int(v) for k, v in attack_counts.items()},
        'events':        unique_events[:100],
        'top_attackers': top_attackers[:10],
        'summary_logs':  summary_logs,
        'timestamp':     datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ml_model':      'Random Forest + TF-IDF',
        'dataset_size':  int(len(DATASET)),
    }