# Malware Detection Pipeline - Chat Summary

## Project Objective
Operationalize a Kaggle Jupyter notebook for malware classification (using the Oliveira dataset) into a production-ready Python pipeline. The goal is to train a model on API call sequences and use it for inference (predicting whether a new sequence is Malware or Benign).

## Key Discoveries & Issues Fixed
1. **Broken Preprocessing**: The original notebook set up a preprocessing pipeline (scaling + SMOTE for class imbalance) but then accidentally overwrote the variables and trained on raw, imbalanced data. *Fix: Built a consistent `split -> scale -> SMOTE` pipeline.*
2. **Embedding Mismatch**: The CNN-LSTM model expects integer API indices, but the data was being passed as floats. *Fix: Created separate integer arrays specifically for the embedding-based models.*
3. **API Mapping Ignored**: The original code never used `api_list.txt`. *Fix: Integrated `api_list.txt` to map API names to indices (0-306) and vice versa, which is critical for inference.*
4. **Severe Class Imbalance Bias**: The dataset has 42,797 malware vs 1,079 benign samples. Early 5-epoch training resulted in models predicting "Malware" for everything (100% confidence).
   *Fix: Implemented three major changes to combat bias:*
   - Increased training from 5 to **50 epochs**.
   - Added **focal loss** to down-weight easy examples and focus on hard ones.
   - Applied **`class_weight='balanced'`** to all models.
5. **Inference TypeError**: Loading the custom focal loss model via `tf.keras.models.load_model` threw an error during inference. *Fix: Added `compile=False` when loading the `.h5` model since loss functions aren't needed for prediction.*

## Current Pipeline Architecture
We created two standalone scripts:

1. **`malware_pipeline.py` (Training)**
   - Loads dataset and `api_list.txt`.
   - Balances data via SMOTE and scales it.
   - Currently configured to train **7 different ANN architectures** (Simple ANN, MLP, Residual ANN, CNN-LSTM, etc.) as a comparative study, mirroring the original Kaggle notebook.
   - Saves trained models as `.h5` files and the scaler as `scaler.joblib`.

2. **`test_inference.py` (Production Inference)**
   - Loads the saved `.h5` model and the scaler.
   - Takes a raw sequence of 100 API names (e.g., `["NtOpenProcess", "LdrLoadDll", ...]`).
   - Translates names to integer indices using `api_list.txt`.
   - Scales the input and predicts Malware/Benign with a confidence score.
   - Currently configured with real benign and malware test samples extracted directly from the dataset.

## Pending Decision / Next Steps
The `malware_pipeline.py` script currently trains all 7 models, which takes ~2-3 hours. Since the MLP and Residual ANN models performed the best (98.2% accuracy), the immediate next step proposed was to strip out the other 6 models. This would reduce the training time to ~20 minutes while yielding the exact same production-ready inference model.
