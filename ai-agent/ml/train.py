"""
Fine-tuning Script for DeepSeek Coder.

This script uses the `unsloth` library to fine-tune a quantization-optimized DeepSeek Coder model
using the feedback provided by users. It uses LoRA (Low-Rank Adaptation) for efficient training.
"""

# Import FastLanguageModel from unsloth for efficient fine-tuning
from unsloth import FastLanguageModel
# Import torch for tensor operations
import torch
# Import load_dataset from huggingface datasets
from datasets import load_dataset
# Import SFTTrainer for Supervised Fine-Tuning
from trl import SFTTrainer
# Import TrainingArguments for configuration
from transformers import TrainingArguments

# 1. Load Model & Tokenizer
# Load the pre-trained DeepSeek Coder model in 4-bit quantization
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = "unsloth/deepseek-coder-v2-lite-instruct-bnb-4bit",
    max_seq_length = 2048,
    load_in_4bit = True,
)

# 2. Add LoRA Adapters
# Configure Low-Rank Adaptation (LoRA) for efficient updating of model weights
model = FastLanguageModel.get_peft_model(
    model,
    r = 16, # Rank of the LoRA matrices
    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj"], # Target attention modules
    lora_alpha = 16, # Scaling factor
    lora_dropout = 0, # Dropout probability
)

# 3. Load Exported Data
# Load the JSONL dataset containing security feedback
dataset = load_dataset("json", data_files="security_feedback.jsonl", split="train")

# 4. Define Trainer
# Initialize the SFTTrainer with model, dataset, and arguments
trainer = SFTTrainer(
    model = model,
    tokenizer = tokenizer,
    train_dataset = dataset,
    dataset_text_field = "text", # Field containing the training text
    max_seq_length = 2048,
    args = TrainingArguments(
        per_device_train_batch_size = 2, # Batch size per GPU
        gradient_accumulation_steps = 4, # accumulate gradients to simulate larger batch size
        warmup_steps = 5, # Linear warmup steps
        max_steps = 60, # Total training steps (Adjust based on dataset size)
        learning_rate = 2e-4, # Learning rate
        fp16 = not torch.cuda.is_bf16_supported(), # Use FP16 if BF16 not supported
        bf16 = torch.cuda.is_bf16_supported(), # Use BF16 if supported
        logging_steps = 1,
        output_dir = "outputs", # Directory to save checkpoints
    ),
)

# Start training
trainer.train()
# Save the fine-tuned model merged with base weights (or adapters only)
model.save_pretrained_merged("ai_security_brain_v2", tokenizer, save_method = "merged_16bit")