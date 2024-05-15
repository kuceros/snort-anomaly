# confusion_shap.py
#
# This script loads the labeled dataset and the MinMaxScaler object
# used to normalize the data in the training script. It then loads
# the TensorFlow Lite model and uses it to make predictions on the
# dataset. The predictions are compared with the true labels to
# compute the confusion matrix, accuracy, and F1 score. The script
# then visualizes the confusion matrix and SHAP values for each feature
# using a summary plot.
#
# Usage: python confusion_shap.py -d <labeled.csv> -s <scaling.bin> -m <flow.model>
# Rostislav Kucera <kucera.rosta@gmail.com>, 2024

import pandas as pd
import numpy as np
import tensorflow as tf
import struct
from sklearn.metrics import confusion_matrix, accuracy_score, f1_score
import matplotlib.pyplot as plt
import seaborn as sns
import shap
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Compute and visualize the confusion matrix and SHAP for a TensorFlow Lite model.")
parser.add_argument('-d', '--data', required=True, help="Path to the labeled dataset CSV file.")
parser.add_argument('-s', '--scaler', required=True, help="Path to the scaler info file.")
parser.add_argument('-m', '--model', required=True, help="Path to the TensorFlow Lite model file.")
args = parser.parse_args()

# Load data
data = pd.read_csv(args.data, header=None)  # Load labeled dataset from provided path
X = data.iloc[:, :-1]  # Features
y_true = data.iloc[:, -1]  # True labels

y_true_binary = y_true

# Load scaler info
with open(args.scaler, "rb") as file:  # Load scaler info from provided path
    min_values_len = struct.unpack('<I', file.read(4))[0]
    min_values = np.array(struct.unpack('<' + 'd' * min_values_len, file.read(8 * min_values_len)))

    max_values_len = struct.unpack('<I', file.read(4))[0]
    max_values = np.array(struct.unpack('<' + 'd' * max_values_len, file.read(8 * max_values_len)))

# Normalize data
X_normalized = (X - min_values[:len(X.columns)]) / (max_values[:len(X.columns)] - min_values[:len(X.columns)])

# Load TensorFlow Lite model
interpreter = tf.lite.Interpreter(model_path=args.model)  # Load model from provided path
interpreter.allocate_tensors()

# Get input and output details expected by the model
input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()

# Define function for prediction
def predict(input_data):
    predictions = []
    for row in input_data.values:
        row_reshaped = row.astype(np.float32).reshape(1, -1)
        interpreter.set_tensor(input_details[0]['index'], row_reshaped)
        interpreter.invoke()
        output_data = interpreter.get_tensor(output_details[0]['index'])
        predictions.append(output_data)
        
    return np.array(predictions)

# Get predictions
y_pred = predict(X_normalized)

threshold = 0.9
y_pred_binary = (y_pred > threshold).astype(int)

# Squeeze extra dimensions in y_pred_binary
y_pred_binary = np.squeeze(y_pred_binary)

# Create confusion matrix
conf_matrix = confusion_matrix(y_true_binary, y_pred_binary)

# Compute accuracy
accuracy = accuracy_score(y_true_binary, y_pred_binary)

# Compute F1 score
f1 = f1_score(y_true_binary, y_pred_binary)

plt.figure(figsize=(8, 6))
sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="Blues", cbar=False)

# Set custom tick labels
plt.xticks(ticks=[0.5, 1.5], labels=["Predikované negativní", "Predikované pozitivní"])
plt.yticks(ticks=[0.5, 1.5], labels=["Skutečně negativní", "Skutečně pozitivní"])
plt.xlabel('Predikované třídy')
plt.ylabel('Skutečné třídy')
plt.title(f'Matice záměn')
plt.show()

print("Accuracy:", accuracy)
print("F1 Score:", f1)

# SHAP interpretation
explainer = shap.Explainer(predict, X_normalized)
shap_values = explainer(X_normalized)

# Visualize SHAP summary plot
shap.summary_plot(shap_values, X_normalized, feature_names=data.columns[:-1])
