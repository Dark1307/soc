from modules.dataset import DATASET, LABEL_NAMES
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
import numpy as np

texts  = [d[0] for d in DATASET]
labels = [d[1] for d in DATASET]

pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=(2, 4),
        max_features=5000,
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
y_pred = pipeline.predict(X_test)

print("=" * 55)
print("   ML MODEL ACCURACY REPORT")
print("=" * 55)
print(f"   Total Samples     : {len(texts)}")
print(f"   Training Samples  : {len(X_train)}")
print(f"   Testing Samples   : {len(X_test)}")
print(f"   Overall Accuracy  : {round(accuracy_score(y_test, y_pred) * 100, 2)} %")
print("=" * 55)
print()
print("PER CLASS REPORT:")
print(classification_report(
    y_test, y_pred,
    target_names=list(LABEL_NAMES.values())
))

scores = cross_val_score(pipeline, texts, labels, cv=5)
print("=" * 55)
print("CROSS VALIDATION (5-Fold):")
for i, s in enumerate(scores):
    print(f"   Fold {i+1}  :  {round(s*100, 2)} %")
print(f"   Average :  {round(np.mean(scores)*100, 2)} %")
print(f"   Std Dev :  +/- {round(np.std(scores)*100, 2)} %")
print("=" * 55)