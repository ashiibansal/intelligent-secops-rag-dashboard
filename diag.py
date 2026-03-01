import os
import google.generativeai as genai
from dotenv import load_dotenv

# 1. Force load .env
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

print(f"--------- DIAGNOSTIC START ---------")

# 2. Check if Key exists
if not api_key:
    print("❌ API Key status: MISSING/NONE")
    print("   Action: Check your .env file is in the same folder and named exactly '.env'")
    exit()
else:
    # Print first 5 chars only for security
    print(f"✅ API Key status: FOUND (Starts with: {api_key[:5]}...)")

# 3. Configure Raw Google Client
try:
    genai.configure(api_key=api_key)
    print("✅ Google Client Configured.")
except Exception as e:
    print(f"❌ Configuration Failed: {e}")
    exit()

# 4. List Available Models
print("\n🔍 Querying Google for available models...")
try:
    models = list(genai.list_models())
    embedding_models = [m.name for m in models if 'embedContent' in m.supported_generation_methods]
    
    if not embedding_models:
        print("❌ Connection successful, but NO embedding models found.")
        print("   Action: Enable 'Generative Language API' in Google Cloud Console.")
    else:
        print(f"✅ Found {len(embedding_models)} embedding models:")
        for m in embedding_models:
            print(f"   - {m}")
            
    # 5. Try a Test Embedding
    if embedding_models:
        test_model = embedding_models[0]
        print(f"\n🧪 Testing embedding with: {test_model}...")
        result = genai.embed_content(
            model=test_model,
            content="Hello world",
            task_type="retrieval_document",
            title="Test"
        )
        print("✅ SUCCESS! Embedding generated.")
        print(f"   Shape of vector: {len(result['embedding'])}")
        
except Exception as e:
    print(f"❌ API Error: {e}")

print("--------- DIAGNOSTIC END ---------")