# attack_detector/predictor.py
import os
import numpy as np # type: ignore
import joblib # type: ignore

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load models and scaler
scaler = joblib.load(os.path.join(BASE_DIR, 'models/scaler.pkl'))
xgb = joblib.load(os.path.join(BASE_DIR, 'models/xgboost_model.pkl'))
svm = joblib.load(os.path.join(BASE_DIR, 'models/svm_model.pkl'))
knn = joblib.load(os.path.join(BASE_DIR, 'models/knn_model.pkl'))
mlp = joblib.load(os.path.join(BASE_DIR, 'models/mlp_model.pkl'))
meta_model = joblib.load(os.path.join(BASE_DIR, 'models/meta_model.pkl'))

def predict_attack(input_features):
    features = np.array(input_features, dtype=np.float64).reshape(1, -1)
    scaled_features = scaler.transform(features)

    pred1 = xgb.predict(scaled_features)[0]
    pred2 = svm.predict(scaled_features)[0]
    pred3 = knn.predict(scaled_features)[0]
    pred4 = mlp.predict(scaled_features)[0]

    # Combine scaled features with base model predictions
    stacked_input = np.concatenate([scaled_features.flatten(), [pred1, pred2, pred3, pred4]]).reshape(1, -1)
    final_pred = meta_model.predict(stacked_input)[0]

    return final_pred