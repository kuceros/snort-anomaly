//--------------------------------------------------------------------------
// Copyright (C) 2023-2023 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// libml.cc author Brandon Stultz <brastult@cisco.com>

#include <cstdint>
#include <utility>

#include "tensorflow/lite/interpreter.h"
#include "tensorflow/lite/kernels/kernel_util.h"
#include "tensorflow/lite/kernels/register.h"
#include "tensorflow/lite/logger.h"
#include "tensorflow/lite/model.h"

#include "libml.h"
#include "util.h"
#include "version.h"

using namespace tflite;

const char* libml_version()
{ return VERSION; }

BinaryClassifier::BinaryClassifier() = default;
BinaryClassifier::~BinaryClassifier() = default;

bool BinaryClassifier::build(std::string in)
{
    interpreter.reset();

    LoggerOptions::SetMinimumLogSeverity(TFLITE_LOG_ERROR);

    src = std::move(in);

    model = FlatBufferModel::VerifyAndBuildFromBuffer(src.data(),
        src.size());

    if(model == nullptr)
        return false;

    ops::builtin::BuiltinOpResolver resolver;

    std::unique_ptr<Interpreter> check;

    InterpreterBuilder builder(*model, resolver);

    if(builder(&check) != kTfLiteOk)
        return false;

    if(check->inputs().size() != 1 &&
        check->outputs().size() != 1)
        return false;

    const TfLiteTensor* input_tensor = check->input_tensor(0);
    const TfLiteTensor* output_tensor = check->output_tensor(0);

    if(input_tensor->type != kTfLiteFloat32 &&
        output_tensor->type != kTfLiteFloat32)
        return false;

    int64_t sz = NumElements(input_tensor);

    if(sz <= 0)
        return false;

    input_size = (size_t)sz;

    if(NumElements(output_tensor) != 1)
        return false;

    if(check->AllocateTensors() != kTfLiteOk)
        return false;

    interpreter = std::move(check);
    return true;
}

bool BinaryClassifier::buildFlowModel(std::string model_path) {
    // Reset the interpreter
    interpreter.reset();

    // Set minimum log severity for TensorFlow Lite
    LoggerOptions::SetMinimumLogSeverity(TFLITE_LOG_ERROR);

    // Load the model from the specified file
    model = tflite::FlatBufferModel::BuildFromFile(model_path.c_str());
    if (!model) {
        // Failed to load the model, return false
        return false;
    }

    // Create an interpreter builder and resolver
    tflite::ops::builtin::BuiltinOpResolver resolver;
    std::unique_ptr<tflite::Interpreter> temp_interpreter;

    // Create the interpreter
    tflite::InterpreterBuilder builder(*model, resolver);
    if (builder(&temp_interpreter) != kTfLiteOk || !temp_interpreter) {
        // Failed to create the interpreter, return false
        return false;
    }

    // Ensure the model has exactly one input tensor and one output tensor
    if (temp_interpreter->inputs().size() != 1 || temp_interpreter->outputs().size() != 1) {
        // Model does not have the expected number of inputs or outputs, return false
        return false;
    }

    // Get input and output tensors
    const TfLiteTensor* input_tensor = temp_interpreter->input_tensor(0);
    const TfLiteTensor* output_tensor = temp_interpreter->output_tensor(0);

    // Ensure input and output tensor types are float32
    if (input_tensor->type != kTfLiteFloat32 || output_tensor->type != kTfLiteFloat32) {
        // Input or output tensor types are not float32, return false
        return false;
    }

    // Allocate tensors for the interpreter
    if (temp_interpreter->AllocateTensors() != kTfLiteOk) {
        // Failed to allocate tensors, return false
        return false;
    }

    // Move the interpreter to the member variable
    interpreter = std::move(temp_interpreter);

    // Model and interpreter were successfully initialized, return true
    return true;
}

bool BinaryClassifier::buildFromFile(const std::string& path)
{
    std::string data;

    if(!readFile(path, data))
    {
        interpreter.reset();
        return false;
    }

    return build(std::move(data));
}

bool BinaryClassifier::run(const char* buffer,
    size_t buffer_size, float& output)
{
    if(buffer_size == 0)
        return false;

    if(interpreter == nullptr)
        return false;

    if(interpreter->ResetVariableTensors() != kTfLiteOk)
        return false;

    if(buffer_size > input_size)
        buffer_size = input_size;

    size_t pad_size = input_size - buffer_size;

    float* input = interpreter->typed_input_tensor<float>(0);

    for(size_t i = 0; i < pad_size; i++)
        input[i] = (float)0;

    for(size_t i = 0; i < buffer_size; i++)
    {
        uint8_t byte = (uint8_t)buffer[i];
        input[pad_size + i] = (float)byte;
    }

    if(interpreter->Invoke() != kTfLiteOk)
        return false;

    output = *interpreter->typed_output_tensor<float>(0);
    return true;
}

bool BinaryClassifier::runFlowModel(float value1, float value2, float value3, float value4, float value5, float& output)
{
    if(interpreter == nullptr)
        return false;

    if(interpreter->ResetVariableTensors() != kTfLiteOk)
        return false;

    float* input = interpreter->typed_input_tensor<float>(0);

    input[0] = value1;
    input[1] = value2;
    input[2] = value3;
    input[3] = value4;
    input[4] = value5;

    if(interpreter->Invoke() != kTfLiteOk)
        return false;

    output = *interpreter->typed_output_tensor<float>(0);
    return true;
}
