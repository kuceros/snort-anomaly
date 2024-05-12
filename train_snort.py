# train_snort.py
#
# This script trains a neural network model
# on the labeled dataset from Snort IntervalDetector module
# and saves the model in TensorFlow Lite format.
# The script also saves the MinMaxScaler object used to 
# normalize the data in a binary file for normalizing
# the new data before predictions.
#
# Usage: python train_snort.py <csv_file>
# Rostislav Kucera <kucera.rosta@gmail.com>, 2024

import sys
import pandas as pd
import numpy as np
import tensorflow as tf
import struct
from tensorflow.keras import layers
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split

# Check if the filename is provided as an argument
if len(sys.argv) != 2:
    print("Usage: python script.py <csv_file>")
    sys.exit(1)

# Get the filename from command-line arguments
csv_file = sys.argv[1]

data = pd.read_csv(csv_file, header=None)
X = data.iloc[:, :-1]  # Features
Y = data.iloc[:, -1]   # Labels

# Normalize data
scaler = MinMaxScaler()
X_normalized = scaler.fit_transform(X)

# Split data into training and testing sets
X_train, X_test, Y_train, Y_test = train_test_split(X_normalized, Y, test_size=0.2, random_state=42)

# Build model
model = tf.keras.Sequential([
    layers.Input(shape=(X_normalized.shape[1],)), 
    layers.Dense(32, activation='relu'),
    layers.Dense(16, activation='relu'),
    layers.Dense(1, activation='sigmoid')
])

model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
model.summary()

# Define early stopping callback
early_stopping = EarlyStopping(monitor='val_loss', patience=10, verbose=1, restore_best_weights=True)


# Train Model
model.fit(X_train, Y_train, epochs=100, batch_size=32, validation_data=(X_test, Y_test), callbacks=[early_stopping])

# Evaluate Model
loss, accuracy = model.evaluate(X_test, Y_test)
print("Test Loss:", loss)
print("Test Accuracy:", accuracy)

# Save Model
model.save('model')

# Convert the saved model to TensorFlow Lite format
converter = tf.lite.TFLiteConverter.from_saved_model('model')
converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS, tf.lite.OpsSet.SELECT_TF_OPS]
converter._experimental_lower_tensor_list_ops = False
tflite_model = converter.convert()

# Save the TensorFlow Lite model to a file
with open('flowml.model', 'wb') as f:
    f.write(tflite_model)


scaler = MinMaxScaler()
scaler.fit(X)

min_values = scaler.data_min_
max_values = scaler.data_max_

# Save the min and max values to a binary file
with open("scaling.bin", "wb") as file:
    file.write(struct.pack('<I', len(min_values)))
    file.write(struct.pack('<' + 'd'*len(min_values), *min_values))
    
    file.write(struct.pack('<I', len(max_values)))
    file.write(struct.pack('<' + 'd'*len(max_values), *max_values))
