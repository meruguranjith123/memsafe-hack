import streamlit as st
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import openai
from datetime import datetime

# Add project root to Python path so we can import utils
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from utils.json_parser import extract_json
from utils.snippet_extractor import extract_snippet_from_lines, fallback_extract_snippet_from_pattern
from utils.severity import calculate_safety_score, severity_to_score
from utils.ai_providers import call_ai_provider
from utils.pdf_generator import generate_pdf_report

# Load environment variables
load_dotenv()

# Initialize OpenAI API key
openai.api_key = os.getenv('OPENAI_API_KEY')

# Load prompt template
PROMPT_TEMPLATE_PATH = Path(__file__).parent.parent / 'utils' / 'prompt_template.txt'
try:
    PROMPT_TEMPLATE = PROMPT_TEMPLATE_PATH.read_text()
except FileNotFoundError:
    st.error("Error: Could not find prompt template file.")
    st.stop()

# Streamlit UI
st.title('MemSafe — C to Rust Safety Assistant')
st.markdown('Analyze C code for memory safety vulnerabilities and get Rust-based solutions.')

# Education section (collapsible)
with st.expander("📚 Why Rust is Safer?", expanded=False):
    st.markdown("""
    ### Memory Safety Guarantees
    
    **Rust prevents entire classes of bugs at compile time:**
    
    - ✅ **No Buffer Overflows**: Rust's ownership system prevents out-of-bounds access
    - ✅ **No Use-After-Free**: The borrow checker ensures memory is valid when used
    - ✅ **No Null Pointer Dereferences**: Rust uses `Option<T>` instead of null pointers
    - ✅ **No Data Races**: Rust's type system prevents concurrent data access bugs
    - ✅ **Automatic Memory Management**: No manual `malloc`/`free` needed
    
    ### How Rust Achieves This
    
    1. **Ownership System**: Each value has a single owner, preventing dangling pointers
    2. **Borrow Checker**: Analyzes code at compile time to ensure memory safety
    3. **Type System**: Strong types prevent many common errors
    4. **Zero-Cost Abstractions**: Safety without runtime overhead
    
    ### Real-World Impact
    
    - **70% of security vulnerabilities** in C/C++ are memory safety issues
    - Rust eliminates these vulnerabilities **at compile time**
    - Used in production by: Mozilla, Microsoft, Google, Amazon, and more
    """)

# Input method selection
input_method = st.radio(
    "Choose input method:",
    ["📝 Paste Code", "📂 Upload File"],
    horizontal=True
)

code_input = ""

if input_method == "📂 Upload File":
    uploaded_file = st.file_uploader("Upload a C file", type=['c', 'h', 'cpp', 'hpp'], help="Upload a .c, .h, .cpp, or .hpp file")
    if uploaded_file is not None:
        code_input = uploaded_file.read().decode('utf-8')
        st.text_area('Uploaded Code Preview', code_input, height=200, disabled=True)
    else:
        st.info("👆 Please upload a C file above")
else:
    code_input = st.text_area('Paste C code here', height=300, placeholder='// Paste your C code here...')

# Provider and model selection (always visible)
st.markdown("---")
st.markdown("**⚙️ Settings**")
col1, col2 = st.columns(2)

with col1:
    # Provider selection
    provider = st.selectbox(
        "AI Provider",
        ["OpenAI (Free Tier Available!)", "Hugging Face (Currently Unavailable)"],
        help="OpenAI offers $5 free credits for new accounts (no credit card needed initially)"
    )
    
    # Show warning if Hugging Face selected
    if provider == "Hugging Face (Currently Unavailable)":
        st.error("⚠️ Hugging Face API is currently unavailable (all models returning 410/404 errors).")
        st.info("💡 **Recommendation**: Use 'OpenAI (Free Tier Available!)' - new accounts get $5 free credits with no credit card required!")

with col2:
    # Model selection based on provider
    if provider == "Hugging Face (Currently Unavailable)":
        st.info("⚠️ Note: Many HF models are currently unavailable. Using fallback approach.")
        model_name = st.selectbox(
            "Model (Auto-fallback if unavailable)",
            [
                "Auto (Recommended)",  # Will try multiple models
                "bigscience/bloom-560m",
                "gpt2",
                "distilgpt2",
                "microsoft/Phi-3-mini-4k-instruct",
                "mistralai/Mistral-7B-Instruct-v0.2"
            ],
            help="If 'Auto' is selected, the app will try multiple models until one works"
        )
        provider_key = "huggingface"
        use_auto_fallback = (model_name == "Auto (Recommended)")
    elif provider == "OpenAI (Free Tier Available!)":  # OpenAI
        st.success("✅ GPT-3.5-turbo selected (recommended - cheaper and works great!)")
        use_cheaper_model = st.checkbox(
            "Use GPT-4o instead (more expensive)", 
            value=False,
            help="GPT-4o is better but costs more. GPT-3.5-turbo is recommended for free tier."
        )
        model_name = 'gpt-4o' if use_cheaper_model else 'gpt-3.5-turbo'  # Default to cheaper
        provider_key = "openai"
    else:
        provider_key = "openai"  # Default fallback
        model_name = "gpt-3.5-turbo"

if st.button('Analyze', type='primary'):
    if not code_input or not code_input.strip():
        st.warning('⚠️ Please paste some C code first!')
    else:
        # Check for API key based on provider
        if provider_key == "openai":
            api_key = openai.api_key or os.getenv('OPENAI_API_KEY')
            if not api_key:
                st.error('❌ Error: OPENAI_API_KEY not found in environment variables.')
                st.info('Please set your OpenAI API key in a .env file or environment variables.')
                st.stop()
            
            # Validate API key format
            if not api_key.startswith('sk-'):
                st.error('❌ Invalid API key format. OpenAI API keys should start with "sk-"')
                st.info('Please check your .env file and ensure the key starts with "sk-"')
                st.stop()
            
            if len(api_key) < 20:
                st.warning('⚠️ API key seems too short. Valid OpenAI keys are typically 51+ characters.')
            
            # Update the key for use
            openai.api_key = api_key
        elif provider_key == "huggingface":
            hf_token = os.getenv('HUGGINGFACE_API_TOKEN')
            if not hf_token:
                st.error('❌ Error: HUGGINGFACE_API_TOKEN not found.')
                with st.expander("🔧 How to get a FREE Hugging Face token", expanded=True):
                    st.markdown("""
                    **It's completely FREE - no credit card needed!**
                    
                    1. Go to https://huggingface.co/join (create free account)
                    2. Go to https://huggingface.co/settings/tokens
                    3. Click "New token" → Name it (e.g., "memsafe") → Select "Read" permission
                    4. Copy the token (starts with `hf_...`)
                    5. Add to your `.env` file: `HUGGINGFACE_API_TOKEN=hf_your_token_here`
                    6. Restart the app
                    
                    **That's it! No payment required!** 🎉
                    """)
                st.stop()
        
        prompt = PROMPT_TEMPLATE.replace('<USER_CODE>', code_input)
        
        with st.spinner(f'🔍 Analyzing code with {provider}...'):
            try:
                # Use auto-fallback for Hugging Face if selected
                if provider_key == "huggingface" and use_auto_fallback:
                    from utils.ai_providers_simple import call_huggingface_simple
                    txt = call_huggingface_simple(prompt)
                else:
                    # Use unified provider interface
                    txt = call_ai_provider(provider_key, prompt, model_name)
                
            except Exception as e:
                error_msg = str(e)
                error_type = type(e).__name__
                
                # Handle Hugging Face specific errors
                if 'Hugging Face' in error_msg or '410' in error_msg or 'no longer available' in error_msg.lower():
                    st.error('❌ Model unavailable or error with Hugging Face API.')
                    with st.expander("🔧 Solutions", expanded=True):
                        st.markdown("""
                        **Common issues:**
                        1. **Model loading (503)**: First request takes 30-60 seconds. Wait and try again.
                        2. **Model unavailable (410)**: The selected model is no longer available. Try a different model.
                        3. **Rate limit (429)**: Free tier has limits. Wait 30-60 seconds and try again.
                        
                        **Quick fixes:**
                        - Try a different model from the dropdown
                        - Wait 1 minute and try again (if model is loading)
                        - Check your token is valid at https://huggingface.co/settings/tokens
                        """)
                    st.info('💡 Try selecting a different model from the dropdown above!')
                    st.stop()
                
                # Handle specific OpenAI errors
                if 'AuthenticationError' in error_type or 'authentication' in error_msg.lower() or 'invalid_api_key' in error_msg.lower():
                    st.error('❌ Authentication failed. Please check your OpenAI API key.')
                    with st.expander("🔧 Troubleshooting", expanded=True):
                        st.markdown("""
                        **Common issues:**
                        1. **Invalid or expired key**: Get a new key from https://platform.openai.com/api-keys
                        2. **Wrong format**: Keys should start with `sk-` and be 51+ characters
                        3. **Missing key**: Make sure your `.env` file contains: `OPENAI_API_KEY=sk-your-key-here`
                        4. **Key revoked**: Check your OpenAI account for any restrictions
                        
                        **To fix:**
                        - Open your `.env` file in the project root
                        - Update the `OPENAI_API_KEY` value
                        - Make sure there are no extra spaces or quotes
                        - Restart the Streamlit app
                        """)
                elif 'RateLimitError' in error_type or 'rate limit' in error_msg.lower() or 'quota' in error_msg.lower() or 'insufficient_quota' in error_msg.lower():
                    st.error('❌ Rate limit or quota exceeded.')
                    with st.expander("💡 Solutions", expanded=True):
                        st.markdown("""
                        **What this means:**
                        - Your API key is working, but you've hit usage limits
                        - This could be rate limits (too many requests) or quota limits (no credits)
                        
                        **🎉 FREE SOLUTION - Switch to Hugging Face!**
                        - **No credit card needed!** Switch to "Hugging Face (FREE)" in the settings
                        - Get a free token at https://huggingface.co/settings/tokens
                        - Works great for code analysis and is completely free!
                        
                        **Other options:**
                        1. **Check your usage**: Visit https://platform.openai.com/usage
                        2. **Add billing**: Go to https://platform.openai.com/account/billing (requires payment)
                        3. **Wait a bit**: If it's a rate limit, wait a few minutes and try again
                        """)
                    st.info('🎁 **FREE Alternative**: Switch to "Hugging Face (FREE)" provider above - no payment needed!')
                elif 'APIError' in error_type or 'api' in error_type.lower():
                    st.error(f'❌ OpenAI API error: {error_msg}')
                else:
                    st.error(f'❌ Unexpected error: {error_msg}')
                    st.exception(e)  # Show full traceback for debugging
                st.stop()
        
        # Parse JSON with robust fallback
        parsed_data = extract_json(txt)
        
        if parsed_data is None:
            st.error('❌ Failed to parse model output as JSON. The AI response may be malformed.')
            st.expander('Raw AI Response', expanded=True).code(txt, language='text')
            st.info('💡 Tip: The model may have returned text outside of JSON format. Try analyzing again.')
            st.stop()
        
        # Validate and process the parsed data
        vulnerabilities = parsed_data.get('vulnerabilities', [])
        if not isinstance(vulnerabilities, list):
            st.warning('⚠️ Invalid vulnerabilities format. Expected a list.')
            vulnerabilities = []
        
        # Calculate safety score if not provided or invalid
        safety_score = parsed_data.get('safety_score')
        if safety_score is None or not isinstance(safety_score, (int, float)):
            # Calculate from vulnerabilities
            safety_score = calculate_safety_score(vulnerabilities)
            st.info('ℹ️ Safety score calculated from vulnerabilities (model did not provide one).')
        else:
            # Ensure score is in valid range
            safety_score = max(0, min(100, int(safety_score)))
        
        # Display Summary
        st.subheader('📋 Summary')
        summary = parsed_data.get('summary', 'No summary provided.')
        if summary:
            st.write(summary)
        else:
            st.info('No summary available.')
        
        # Display Safety Score
        st.subheader('🛡️ Safety Score')
        score_color = 'normal'
        if safety_score >= 80:
            score_color = 'normal'
        elif safety_score >= 60:
            score_color = 'normal'
        elif safety_score >= 30:
            score_color = 'off'
        else:
            score_color = 'inverse'
        
        st.metric('Score', f"{safety_score} / 100", delta=None)
        
        # Display Vulnerabilities
        st.subheader('🚨 Vulnerabilities')
        if not vulnerabilities:
            st.success('✅ No vulnerabilities detected!')
        else:
            st.info(f'Found {len(vulnerabilities)} vulnerability/vulnerabilities.')
            
            for idx, v in enumerate(vulnerabilities, 1):
                with st.expander(f"**{idx}. {v.get('type', 'Unknown Vulnerability')} — {v.get('severity', 'Unknown')} (CWE-{v.get('cwe', 'N/A')})**", expanded=True):
                    # Explanation
                    explanation = v.get('explanation', 'No explanation provided.')
                    st.write(explanation)
                    
                    # Extract insecure snippet
                    start_line = v.get("insecure_snippet_start_line")
                    end_line = v.get("insecure_snippet_end_line")
                    pattern = v.get("pattern", "")
                    
                    snippet = ""
                    extraction_method = None
                    
                    # Try line-based extraction first
                    if start_line is not None and end_line is not None:
                        snippet = extract_snippet_from_lines(code_input, start_line, end_line)
                        if snippet:
                            extraction_method = f"Lines {start_line}-{end_line}"
                    
                    # Fallback to pattern matching
                    if not snippet and pattern:
                        snippet = fallback_extract_snippet_from_pattern(code_input, pattern)
                        if snippet:
                            extraction_method = "Pattern matching"
                    
                    # Display snippet
                    if snippet:
                        st.markdown("**Insecure Code Snippet:**")
                        st.code(snippet, language="c")
                        if extraction_method:
                            st.caption(f"Extracted via: {extraction_method}")
                    else:
                        st.warning("⚠️ Could not extract code snippet. Line numbers or pattern may be invalid.")
                        if start_line or end_line:
                            st.caption(f"Attempted lines: {start_line}-{end_line}")
                        if pattern:
                            st.caption(f"Attempted pattern: {pattern}")
        
        # Before/After Comparison View
        st.subheader('📊 Before/After Comparison')
        suggested_rust = parsed_data.get('suggested_rust', [])
        
        if suggested_rust and isinstance(suggested_rust, list) and len(suggested_rust) > 0:
            # Combine all Rust fixes for comparison
            combined_rust = "\n\n".join([
                fix.get('rust_snippet', '') 
                for fix in suggested_rust 
                if isinstance(fix, dict) and fix.get('rust_snippet')
            ])
            
            if combined_rust:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**🔴 Insecure C Code**")
                    st.code(code_input, language='c')
                with col2:
                    st.markdown("**🟢 Safer Rust Alternative**")
                    st.code(combined_rust, language='rust')
            else:
                st.info('Rust code suggestions will appear here after analysis.')
        else:
            st.info('No Rust suggestions available for comparison.')
        
        # Display Suggested Rust Fixes (Detailed)
        st.subheader('🦀 Suggested Rust Fixes (Detailed)')
        
        if not suggested_rust:
            st.info('No Rust suggestions provided by the model.')
        else:
            if not isinstance(suggested_rust, list):
                st.warning('⚠️ Invalid suggested_rust format. Expected a list.')
                suggested_rust = []
            
            # Match Rust fixes with vulnerabilities
            for idx, rust_fix in enumerate(suggested_rust, 1):
                if not isinstance(rust_fix, dict):
                    continue
                
                rust_snippet = rust_fix.get('rust_snippet', '')
                why_safe = rust_fix.get('why_safe', '')
                
                if rust_snippet or why_safe:
                    st.markdown(f"**Fix #{idx}:**")
                    if rust_snippet:
                        st.code(rust_snippet, language='rust')
                    if why_safe:
                        st.write(f"**Why it's safer:** {why_safe}")
                    st.divider()
        
        # PDF Report Generation
        st.subheader('📄 Generate Report')
        try:
            pdf_buffer = generate_pdf_report(parsed_data, code_input)
            if pdf_buffer:
                st.download_button(
                    label="📥 Download PDF Report",
                    data=pdf_buffer.getvalue(),
                    file_name=f"memsafe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    type="primary"
                )
                st.success("✅ PDF report ready for download!")
        except Exception as e:
            st.warning(f"⚠️ PDF generation failed: {str(e)}")
            st.info("The report will still be available in the UI above.")

# Footer
st.markdown("---")
st.caption("MemSafe — Memory Safety Analysis Tool | Powered by OpenAI GPT-4")
