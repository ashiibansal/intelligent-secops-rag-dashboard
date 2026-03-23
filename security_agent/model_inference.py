#!/usr/bin/env python3
"""
CSE-CIC-IDS2018 Model Inference Module
Loads trained models and provides prediction interface for Streamlit application
"""

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
import json
import warnings
from typing import Dict, Tuple, List, Optional

warnings.filterwarnings('ignore')

class CSE_CIC_IDS2018_Predictor:
    def __init__(self, models_dir="trained_models"):
        """
        Initialize the predictor with trained models
        
        Args:
            models_dir (str): Directory containing trained models and artifacts
        """
        self.models_dir = Path(models_dir)
        self.models = {}
        self.preprocessors = {}
        self.label_encoders = {}
        self.feature_columns = None
        self.training_results = None
        
        # Model performance tracking
        self.model_info = {}
        
        self._load_artifacts()
    
    def _load_artifacts(self):
        """Load all trained models and preprocessing artifacts"""
        if not self.models_dir.exists():
            raise FileNotFoundError(f"Models directory not found: {self.models_dir}")
        
        print(f"Loading models from: {self.models_dir}")
        
        # Load feature columns
        feature_file = self.models_dir / "feature_columns.joblib"
        if feature_file.exists():
            self.feature_columns = joblib.load(feature_file)
            print(f"✅ Loaded {len(self.feature_columns)} feature columns")
        
        # Load training results
        results_file = self.models_dir / "training_results.json"
        if results_file.exists():
            with open(results_file, 'r') as f:
                self.training_results = json.load(f)
            print("✅ Loaded training results")
        
        # Load preprocessors
        for prep_file in self.models_dir.glob("*_scaler.joblib"):
            prep_name = prep_file.stem
            self.preprocessors[prep_name] = joblib.load(prep_file)
            print(f"✅ Loaded preprocessor: {prep_name}")
        
        # Load label encoders
        for enc_file in self.models_dir.glob("*_encoder.joblib"):
            enc_name = enc_file.stem.replace("_encoder", "")
            self.label_encoders[enc_name] = joblib.load(enc_file)
            print(f"✅ Loaded encoder: {enc_name}")
        
        # Load models
        for model_file in self.models_dir.glob("*.joblib"):
            if not any(keyword in model_file.name for keyword in ['scaler', 'encoder', 'feature_columns']):
                model_name = model_file.stem
                self.models[model_name] = joblib.load(model_file)
                print(f"✅ Loaded model: {model_name}")
                
                # Store model info
                if self.training_results:
                    self._extract_model_info(model_name)
        
        print(f"\n📊 Summary:")
        print(f"   - Models loaded: {len(self.models)}")
        print(f"   - Preprocessors loaded: {len(self.preprocessors)}")
        print(f"   - Encoders loaded: {len(self.label_encoders)}")
    
    def _extract_model_info(self, model_name):
        """Extract model performance information"""
        model_type = 'binary' if 'binary' in model_name else 'multiclass'
        clean_name = model_name.replace('binary_', '').replace('multiclass_', '')
        
        if model_type in self.training_results and clean_name in self.training_results[model_type + '_classification']:
            info = self.training_results[model_type + '_classification'][clean_name]
            self.model_info[model_name] = {
                'type': model_type,
                'accuracy': info.get('test_accuracy', 0),
                'f1_score': info.get('test_f1_score', 0),
                'display_name': info.get('model_name', clean_name),
                'classes': info.get('classes', [])
            }
    
    def preprocess_data(self, data: pd.DataFrame, model_type: str = 'binary') -> np.ndarray:
        """
        Preprocess input data for model prediction
        
        Args:
            data (pd.DataFrame): Input data to preprocess
            model_type (str): Type of model ('binary' or 'multiclass')
            
        Returns:
            np.ndarray: Preprocessed data ready for prediction
        """
        # Ensure we have the required feature columns
        if self.feature_columns is None:
            raise ValueError("Feature columns not loaded. Please check if feature_columns.joblib exists.")
        
        # Handle different input formats
        df = data.copy()
        
        # Remove non-feature columns if present
        non_feature_cols = ['Label', 'Flow ID', 'Src IP', 'Dst IP', 'Timestamp', 'source_file']
        for col in non_feature_cols:
            if col in df.columns:
                df = df.drop(columns=[col])
        
        # Ensure all required features are present
        missing_features = set(self.feature_columns) - set(df.columns)
        if missing_features:
            print(f"⚠️  Warning: Missing features: {list(missing_features)[:5]}...")
            # Add missing features with default values (0)
            for feature in missing_features:
                df[feature] = 0
        
        # Select and reorder features to match training
        df = df[self.feature_columns]
        
        # Handle missing values
        df = df.fillna(0)
        
        # Replace infinity values
        df = df.replace([np.inf, -np.inf], 0)
        
        # Apply scaling
        scaler_name = f'{model_type}_scaler'
        if scaler_name in self.preprocessors:
            scaled_data = self.preprocessors[scaler_name].transform(df)
        else:
            print(f"⚠️  Warning: Scaler for {model_type} not found. Using raw data.")
            scaled_data = df.values
        
        return scaled_data
    
    def predict_anomaly(self, data: pd.DataFrame, model_name: str = None) -> Dict:
        """
        Predict anomalies (binary classification)
        
        Args:
            data (pd.DataFrame): Input data
            model_name (str): Specific model to use (optional)
            
        Returns:
            Dict: Prediction results with confidence scores
        """
        # Select best binary model if not specified
        if model_name is None:
            binary_models = [name for name in self.models.keys() if 'binary' in name]
            if not binary_models:
                raise ValueError("No binary classification models found")
            
            # Choose model with highest F1 score
            if self.model_info:
                model_name = max(binary_models, 
                               key=lambda x: self.model_info.get(x, {}).get('f1_score', 0))
            else:
                model_name = binary_models[0]
        
        # Preprocess data
        X = self.preprocess_data(data, 'binary')
        
        # Get model
        model = self.models[model_name]
        
        # Make predictions
        predictions = model.predict(X)
        
        # Get prediction probabilities if available
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(X)
            confidence_scores = np.max(probabilities, axis=1)
            attack_probabilities = probabilities[:, 1] if probabilities.shape[1] > 1 else probabilities[:, 0]
        else:
            confidence_scores = np.ones(len(predictions))
            attack_probabilities = predictions.astype(float)
        
        # Convert predictions to labels
        labels = ['Attack' if pred == 1 else 'Benign' for pred in predictions]
        
        # Calculate summary statistics
        total_samples = len(predictions)
        attack_count = np.sum(predictions)
        benign_count = total_samples - attack_count
        
        attack_percentage = (attack_count / total_samples) * 100
        avg_confidence = np.mean(confidence_scores)
        
        results = {
            'predictions': labels,
            'confidence_scores': confidence_scores.tolist(),
            'attack_probabilities': attack_probabilities.tolist(),
            'summary': {
                'total_samples': total_samples,
                'attack_count': int(attack_count),
                'benign_count': int(benign_count),
                'attack_percentage': round(attack_percentage, 2),
                'average_confidence': round(avg_confidence, 4),
                'model_used': self.model_info.get(model_name, {}).get('display_name', model_name),
                'model_accuracy': round(self.model_info.get(model_name, {}).get('accuracy', 0), 4)
            }
        }
        
        return results
    
    def predict_attack_type(self, data: pd.DataFrame, model_name: str = None) -> Dict:
        """
        Predict specific attack types (multiclass classification)
        
        Args:
            data (pd.DataFrame): Input data
            model_name (str): Specific model to use (optional)
            
        Returns:
            Dict: Prediction results with attack type classifications
        """
        # Select best multiclass model if not specified
        multiclass_models = [name for name in self.models.keys() if 'multiclass' in name]
        if not multiclass_models:
            return {
                'error': 'No multiclass classification models available',
                'predictions': [],
                'confidence_scores': [],
                'summary': {}
            }
        
        if model_name is None:
            # Choose model with highest F1 score
            if self.model_info:
                model_name = max(multiclass_models, 
                               key=lambda x: self.model_info.get(x, {}).get('f1_score', 0))
            else:
                model_name = multiclass_models[0]
        
        # Preprocess data
        X = self.preprocess_data(data, 'multiclass')
        
        # Get model and label encoder
        model = self.models[model_name]
        label_encoder = self.label_encoders.get('multiclass')
        
        if label_encoder is None:
            return {
                'error': 'Label encoder not found for multiclass prediction',
                'predictions': [],
                'confidence_scores': [],
                'summary': {}
            }
        
        # Make predictions
        encoded_predictions = model.predict(X)
        predictions = label_encoder.inverse_transform(encoded_predictions)
        
        # Get prediction probabilities if available
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(X)
            confidence_scores = np.max(probabilities, axis=1)
            
            # Get top 3 predictions for each sample
            top_predictions = []
            for i, prob_dist in enumerate(probabilities):
                top_indices = np.argsort(prob_dist)[-3:][::-1]
                top_classes = label_encoder.inverse_transform(top_indices)
                top_probs = prob_dist[top_indices]
                
                top_predictions.append([
                    {
                        'class': cls,
                        'probability': round(float(prob), 4)
                    }
                    for cls, prob in zip(top_classes, top_probs)
                ])
        else:
            confidence_scores = np.ones(len(predictions))
            top_predictions = [[{'class': pred, 'probability': 1.0}] for pred in predictions]
        
        # Calculate summary statistics
        from collections import Counter
        prediction_counts = Counter(predictions)
        
        results = {
            'predictions': predictions.tolist(),
            'confidence_scores': confidence_scores.tolist(),
            'top_predictions': top_predictions,
            'summary': {
                'total_samples': len(predictions),
                'prediction_distribution': dict(prediction_counts),
                'average_confidence': round(np.mean(confidence_scores), 4),
                'model_used': self.model_info.get(model_name, {}).get('display_name', model_name),
                'model_accuracy': round(self.model_info.get(model_name, {}).get('accuracy', 0), 4),
                'available_classes': list(label_encoder.classes_)
            }
        }
        
        return results
    
    def get_model_info(self) -> Dict:
        """Get information about available models"""
        return {
            'available_models': list(self.models.keys()),
            'model_performance': self.model_info,
            'feature_count': len(self.feature_columns) if self.feature_columns else 0,
            'training_metadata': self.training_results.get('training_metadata', {}) if self.training_results else {}
        }
    
    def validate_input_data(self, data: pd.DataFrame) -> Dict:
        """
        Validate input data format and quality
        
        Args:
            data (pd.DataFrame): Input data to validate
            
        Returns:
            Dict: Validation results
        """
        issues = []
        warnings = []
        
        # Check if data is empty
        if data.empty:
            issues.append("Input data is empty")
            return {'valid': False, 'issues': issues, 'warnings': warnings}
        
        # Check feature availability
        if self.feature_columns:
            available_features = set(data.columns)
            required_features = set(self.feature_columns)
            
            # Remove known non-feature columns
            non_feature_cols = ['Label', 'Flow ID', 'Src IP', 'Dst IP', 'Timestamp', 'source_file']
            for col in non_feature_cols:
                available_features.discard(col)
            
            missing_features = required_features - available_features
            extra_features = available_features - required_features
            
            if missing_features:
                warnings.append(f"Missing {len(missing_features)} features (will be filled with zeros)")
            
            if extra_features:
                warnings.append(f"Extra features will be ignored: {list(extra_features)[:5]}")
        
        # Check for data quality issues
        numeric_cols = data.select_dtypes(include=[np.number]).columns
        
        if len(numeric_cols) == 0:
            issues.append("No numeric columns found in the data")
        
        # Check for excessive missing values
        missing_percentages = data.isnull().mean()
        high_missing = missing_percentages[missing_percentages > 0.5]
        
        if not high_missing.empty:
            warnings.append(f"High missing values in {len(high_missing)} columns")
        
        # Check for infinite values
        inf_cols = []
        for col in numeric_cols:
            if np.isinf(data[col]).any():
                inf_cols.append(col)
        
        if inf_cols:
            warnings.append(f"Infinite values found in {len(inf_cols)} columns")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings,
            'data_shape': data.shape,
            'numeric_columns': len(numeric_cols)
        }

def create_prediction_interface():
    """
    Create a simple prediction interface for testing
    This can be integrated into Streamlit applications
    """
    
    class PredictionInterface:
        def __init__(self):
            try:
                self.predictor = CSE_CIC_IDS2018_Predictor()
                self.loaded = True
            except Exception as e:
                print(f"Failed to load predictor: {e}")
                self.loaded = False
        
        def predict_file(self, file_path: str, prediction_type: str = 'anomaly') -> Dict:
            """
            Predict on a CSV file
            
            Args:
                file_path (str): Path to CSV file
                prediction_type (str): 'anomaly' or 'attack_type'
                
            Returns:
                Dict: Prediction results
            """
            if not self.loaded:
                return {'error': 'Models not loaded properly'}
            
            try:
                # Load data
                data = pd.read_csv(file_path)
                
                # Validate data
                validation = self.predictor.validate_input_data(data)
                if not validation['valid']:
                    return {'error': f"Data validation failed: {validation['issues']}"}
                
                # Make predictions
                if prediction_type == 'anomaly':
                    results = self.predictor.predict_anomaly(data)
                elif prediction_type == 'attack_type':
                    results = self.predictor.predict_attack_type(data)
                else:
                    return {'error': f"Unknown prediction type: {prediction_type}"}
                
                # Add validation info
                results['validation'] = validation
                
                return results
                
            except Exception as e:
                return {'error': f"Prediction failed: {str(e)}"}
        
        def get_status(self) -> Dict:
            """Get predictor status"""
            if not self.loaded:
                return {
                    'status': 'error',
                    'message': 'Models not loaded',
                    'models': []
                }
            
            info = self.predictor.get_model_info()
            return {
                'status': 'ready',
                'message': 'Models loaded successfully',
                'models': info['available_models'],
                'performance': info['model_performance']
            }
    
    return PredictionInterface()

if __name__ == "__main__":
    # Test the predictor
    try:
        predictor = CSE_CIC_IDS2018_Predictor()
        print("\n🎯 Predictor loaded successfully!")
        
        # Show model info
        info = predictor.get_model_info()
        print(f"\n📊 Available models: {len(info['available_models'])}")
        for model in info['available_models']:
            print(f"   - {model}")
        
        print("\n✅ Ready for predictions!")
        
    except Exception as e:
        print(f"❌ Failed to initialize predictor: {e}")
        print("Make sure to run the training pipeline first!") 