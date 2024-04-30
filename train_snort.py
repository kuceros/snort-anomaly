import pandas as pd
import numpy as np
import tensorflow as tf
import struct
from tensorflow.keras import layers
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split



def min_max_scaling(data, min_vals, max_vals):
    """
    Perform Min-Max scaling on the data using the given minimum and maximum values.

    Args:
    - data: Input data to be scaled (numpy array).
    - min_vals: Minimum values for each feature (numpy array).
    - max_vals: Maximum values for each feature (numpy array).

    Returns:
    - Scaled data (numpy array).
    """
    scaled_data = (data - min_vals) / (max_vals - min_vals)
    return scaled_data


# Load the CSV data


tf.config.set_visible_devices([], 'GPU')
gpus = tf.config.list_physical_devices('GPU')
if gpus:
    print("GPU is available")
    for gpu in gpus:
        print("Device:", gpu)
else:
    print("GPU is not available")

data = pd.read_csv('/Users/kucera.rosta/Desktop/data_labeled.csv', header=None)
X = data.iloc[:, :-1]  # Features
Y = data.iloc[:, -1]   # Labels

# Scale the features
scaler = MinMaxScaler()
X_normalized = scaler.fit_transform(X)

# Split data into training and testing sets
X_train, X_test, Y_train, Y_test = train_test_split(X_normalized, Y, test_size=0.2, random_state=42)

# Build Model (Simple feedforward neural network)
model = tf.keras.Sequential([
    layers.Input(shape=(X_normalized.shape[1],)),  # Adjust input shape
    layers.Dense(32, activation='relu'),
    layers.Dense(16, activation='relu'),
    layers.Dense(1, activation='sigmoid')
])

model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
model.summary()

# Train Model
model.fit(X_train, Y_train, epochs=100, batch_size=32, validation_data=(X_test, Y_test))

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
with open('snort_full.model', 'wb') as f:
    f.write(tflite_model)


scaler = MinMaxScaler()
scaler.fit(X)

min_values = scaler.data_min_
max_values = scaler.data_max_

# Open a binary file in write mode
with open("scaler_info_full.bin", "wb") as file:
    # Write min values count and min values
    file.write(struct.pack('<I', len(min_values)))
    file.write(struct.pack('<' + 'd'*len(min_values), *min_values))
    
    # Write max values count and max values
    file.write(struct.pack('<I', len(max_values)))
    file.write(struct.pack('<' + 'd'*len(max_values), *max_values))

