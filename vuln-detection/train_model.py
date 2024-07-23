import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, precision_recall_fscore_support
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
import numpy as np
from imblearn.over_sampling import SMOTE

# Load the data
data = pd.read_csv('vulnerabilities.csv')

# Map severity levels to numerical values
severity_mapping = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
data['Severity'] = data['Severity'].map(severity_mapping)

# Encode the 'VulnerabilityID' column
label_encoder = LabelEncoder()
data['VulnerabilityID'] = label_encoder.fit_transform(data['VulnerabilityID'])

# Select top N classes
top_n_classes = 50
class_counts = data['VulnerabilityID'].value_counts()
top_classes = class_counts.nlargest(top_n_classes).index
data = data[data['VulnerabilityID'].isin(top_classes)]

# Feature and target separation
X = data[['PkgName', 'InstalledVersion', 'Severity']]
y = data['VulnerabilityID']

# Convert categorical features to numerical
X = pd.get_dummies(X, columns=['PkgName', 'InstalledVersion'])

# Apply SMOTE to handle class imbalance
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, random_state=42, stratify=y_resampled)

# Print class distribution for verification
print("Training set class distribution:\n", pd.Series(y_train).value_counts())
print("Test set class distribution:\n", pd.Series(y_test).value_counts())

# Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Evaluate the model
print(classification_report(y_test, y_pred, zero_division=0))

# Predict probabilities
y_score = model.predict_proba(X_test)

# Binarize the test labels for precision-recall score calculation
one_hot_encoder = OneHotEncoder(sparse_output=False)
y_test_bin = one_hot_encoder.fit_transform(y_test.values.reshape(-1, 1))

# Adjust the predicted probabilities array to match the one-hot encoded labels
n_classes = y_test_bin.shape[1]
y_score_full = np.zeros((len(y_test), n_classes))

for i, class_index in enumerate(model.classes_):
    if class_index < n_classes:
        y_score_full[:, class_index] = y_score[:, i]

# Check dimensions for debugging
print(f'y_test_bin shape: {y_test_bin.shape}')
print(f'y_score_full shape: {y_score_full.shape}')

# Calculate precision, recall, and F1-score
precision, recall, fscore, _ = precision_recall_fscore_support(y_test_bin.argmax(axis=1), y_score_full.argmax(axis=1), average='macro', zero_division=0)
print(f"Precision: {precision}, Recall: {recall}, F-Score: {fscore}")

# Print detailed classification report
print(classification_report(y_test_bin.argmax(axis=1), y_score_full.argmax(axis=1), zero_division=0))
