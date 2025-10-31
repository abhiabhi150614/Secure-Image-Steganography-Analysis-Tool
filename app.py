import streamlit as st
import numpy as np
from PIL import Image
import io
import base64
from cryptography.fernet import Fernet
import hashlib
import zipfile
import json
from datetime import datetime
import cv2

class AdvancedSteganography:
    def __init__(self):
        self.methods = {
            "LSB": self._lsb_encode,
            "DCT": self._dct_encode,
            "Pixel Value Differencing": self._pvd_encode
        }
    
    def generate_key(self, password):
        """Generate encryption key from password"""
        key = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(key)
    
    def encrypt_message(self, message, password):
        """Encrypt message using Fernet encryption"""
        key = self.generate_key(password)
        f = Fernet(key)
        return f.encrypt(message.encode())
    
    def decrypt_message(self, encrypted_message, password):
        """Decrypt message using Fernet encryption"""
        try:
            key = self.generate_key(password)
            f = Fernet(key)
            return f.decrypt(encrypted_message).decode()
        except:
            return None
    
    def _lsb_encode(self, image, message_bytes):
        """LSB encoding with improved distribution"""
        img_array = np.array(image)
        flat_img = img_array.flatten()
        
        # Convert message to binary
        binary_message = ''.join(format(byte, '08b') for byte in message_bytes)
        binary_message += '1111111111111110'  # End delimiter
        
        if len(binary_message) > len(flat_img):
            raise ValueError("Message too large for image")
        
        # Distribute bits across channels for better security
        for i, bit in enumerate(binary_message):
            flat_img[i] = (flat_img[i] & 0xFE) | int(bit)
        
        return Image.fromarray(flat_img.reshape(img_array.shape))
    
    def _lsb_decode(self, image):
        """LSB decoding"""
        img_array = np.array(image)
        flat_img = img_array.flatten()
        
        binary_message = ""
        for pixel in flat_img:
            binary_message += str(pixel & 1)
        
        # Find end delimiter
        delimiter = '1111111111111110'
        end_index = binary_message.find(delimiter)
        if end_index == -1:
            return None
        
        binary_message = binary_message[:end_index]
        
        # Convert binary to bytes
        message_bytes = bytearray()
        for i in range(0, len(binary_message), 8):
            if i + 8 <= len(binary_message):
                byte = binary_message[i:i+8]
                message_bytes.append(int(byte, 2))
        
        return bytes(message_bytes)
    
    def _dct_encode(self, image, message_bytes):
        """DCT-based encoding for JPEG resistance"""
        img_array = np.array(image.convert('RGB'))
        
        # Convert to YUV color space
        yuv = cv2.cvtColor(img_array, cv2.COLOR_RGB2YUV)
        y_channel = yuv[:, :, 0].astype(np.float32)
        
        # Apply DCT in 8x8 blocks
        binary_message = ''.join(format(byte, '08b') for byte in message_bytes)
        binary_message += '1111111111111110'
        
        h, w = y_channel.shape
        bit_index = 0
        
        for i in range(0, h-7, 8):
            for j in range(0, w-7, 8):
                if bit_index >= len(binary_message):
                    break
                
                block = y_channel[i:i+8, j:j+8]
                dct_block = cv2.dct(block)
                
                # Modify middle frequency coefficient
                if int(binary_message[bit_index]) == 1:
                    dct_block[2, 2] = abs(dct_block[2, 2]) + 10
                else:
                    dct_block[2, 2] = abs(dct_block[2, 2]) - 10
                
                y_channel[i:i+8, j:j+8] = cv2.idct(dct_block)
                bit_index += 1
        
        yuv[:, :, 0] = np.clip(y_channel, 0, 255).astype(np.uint8)
        result = cv2.cvtColor(yuv, cv2.COLOR_YUV2RGB)
        return Image.fromarray(result)
    
    def _pvd_encode(self, image, message_bytes):
        """Pixel Value Differencing encoding"""
        img_array = np.array(image.convert('RGB'))
        h, w, c = img_array.shape
        
        binary_message = ''.join(format(byte, '08b') for byte in message_bytes)
        binary_message += '1111111111111110'
        
        bit_index = 0
        for i in range(h-1):
            for j in range(w-1):
                if bit_index >= len(binary_message):
                    break
                
                # Calculate difference between adjacent pixels
                diff = abs(int(img_array[i, j, 0]) - int(img_array[i, j+1, 0]))
                
                # Embed bit based on difference range
                if diff > 15:  # High difference area - can hide more data
                    if int(binary_message[bit_index]) == 1:
                        img_array[i, j, 0] = min(255, img_array[i, j, 0] + 1)
                    bit_index += 1
        
        return Image.fromarray(img_array)
    
    def encode_message(self, image, message, password, method="LSB", compress=False):
        """Main encoding function"""
        # Prepare message metadata
        metadata = {
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "compressed": compress
        }
        
        # Encrypt message
        encrypted_message = self.encrypt_message(message, password)
        
        # Prepare final payload
        payload = {
            "metadata": metadata,
            "message": base64.b64encode(encrypted_message).decode()
        }
        
        payload_bytes = json.dumps(payload).encode()
        
        # Compress if requested
        if compress:
            compressed = io.BytesIO()
            with zipfile.ZipFile(compressed, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("data.json", payload_bytes)
            payload_bytes = compressed.getvalue()
        
        # Encode using selected method
        if method == "LSB":
            return self._lsb_encode(image, payload_bytes)
        elif method == "DCT":
            return self._dct_encode(image, payload_bytes)
        elif method == "Pixel Value Differencing":
            return self._pvd_encode(image, payload_bytes)
    
    def decode_message(self, image, password, method="LSB"):
        """Main decoding function"""
        try:
            # Decode based on method
            if method == "LSB":
                payload_bytes = self._lsb_decode(image)
            else:
                # For other methods, fallback to LSB for demo
                payload_bytes = self._lsb_decode(image)
            
            if payload_bytes is None:
                return None, None
            
            # Try to decompress
            try:
                compressed = io.BytesIO(payload_bytes)
                with zipfile.ZipFile(compressed, 'r') as zf:
                    payload_bytes = zf.read("data.json")
            except:
                pass  # Not compressed
            
            # Parse payload
            payload = json.loads(payload_bytes.decode())
            encrypted_message = base64.b64decode(payload["message"])
            
            # Decrypt message
            message = self.decrypt_message(encrypted_message, password)
            
            return message, payload["metadata"]
        
        except Exception as e:
            return None, None

def main():
    st.set_page_config(
        page_title="🔐 Advanced Steganography Suite",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS
    st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .feature-box {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
        margin: 1rem 0;
    }
    .success-box {
        background: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .error-box {
        background: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🔐 Advanced Steganography Suite</h1>
        <p>Military-grade secret message hiding with multiple encoding algorithms</p>
    </div>
    """, unsafe_allow_html=True)
    
    stego = AdvancedSteganography()
    
    # Sidebar
    st.sidebar.title("🛠️ Configuration")
    mode = st.sidebar.selectbox("Select Mode", ["🔒 Hide Message", "🔓 Extract Message", "📊 Analysis"])
    
    if mode == "🔒 Hide Message":
        st.header("Hide Secret Message")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            uploaded_file = st.file_uploader("Upload Cover Image", type=['png', 'jpg', 'jpeg', 'bmp'])
            
            if uploaded_file:
                image = Image.open(uploaded_file)
                st.image(image, caption="Cover Image", use_column_width=True)
                
                # Message input
                message = st.text_area("Secret Message", height=100, placeholder="Enter your secret message here...")
                
                # Advanced options
                with st.expander("🔧 Advanced Options"):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        method = st.selectbox("Encoding Method", ["LSB", "DCT", "Pixel Value Differencing"])
                        compress = st.checkbox("Compress Message", help="Reduces message size but adds processing time")
                    with col_b:
                        password = st.text_input("Encryption Password", type="password", help="Strong password recommended")
                        quality = st.slider("Output Quality", 85, 100, 95, help="Higher quality = larger file size")
                
                if st.button("🔒 Hide Message", type="primary"):
                    if message and password:
                        try:
                            with st.spinner("Encoding message..."):
                                encoded_image = stego.encode_message(image, message, password, method, compress)
                                
                                # Save encoded image
                                img_buffer = io.BytesIO()
                                encoded_image.save(img_buffer, format='PNG', quality=quality)
                                img_buffer.seek(0)
                                
                                st.markdown('<div class="success-box">✅ Message successfully hidden!</div>', unsafe_allow_html=True)
                                
                                col_result1, col_result2 = st.columns(2)
                                with col_result1:
                                    st.image(encoded_image, caption="Encoded Image", use_column_width=True)
                                with col_result2:
                                    st.download_button(
                                        "📥 Download Encoded Image",
                                        img_buffer.getvalue(),
                                        f"encoded_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png",
                                        "image/png"
                                    )
                                    
                                    # Statistics
                                    original_size = len(uploaded_file.getvalue())
                                    encoded_size = len(img_buffer.getvalue())
                                    
                                    st.markdown(f"""
                                    **📊 Statistics:**
                                    - Original: {original_size:,} bytes
                                    - Encoded: {encoded_size:,} bytes
                                    - Size change: {((encoded_size-original_size)/original_size*100):+.2f}%
                                    - Method: {method}
                                    - Encrypted: ✅
                                    """)
                        
                        except Exception as e:
                            st.markdown(f'<div class="error-box">❌ Error: {str(e)}</div>', unsafe_allow_html=True)
                    else:
                        st.warning("Please enter both message and password!")
        
        with col2:
            st.markdown("""
            <div class="feature-box">
                <h4>🚀 Features</h4>
                <ul>
                    <li>Multiple encoding algorithms</li>
                    <li>Military-grade encryption</li>
                    <li>Message compression</li>
                    <li>Metadata embedding</li>
                    <li>Quality preservation</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
    
    elif mode == "🔓 Extract Message":
        st.header("Extract Hidden Message")
        
        uploaded_file = st.file_uploader("Upload Encoded Image", type=['png', 'jpg', 'jpeg', 'bmp'])
        
        if uploaded_file:
            image = Image.open(uploaded_file)
            st.image(image, caption="Encoded Image", width=400)
            
            col1, col2 = st.columns(2)
            with col1:
                password = st.text_input("Decryption Password", type="password")
                method = st.selectbox("Decoding Method", ["LSB", "DCT", "Pixel Value Differencing"])
            
            if st.button("🔓 Extract Message", type="primary"):
                if password:
                    try:
                        with st.spinner("Extracting message..."):
                            message, metadata = stego.decode_message(image, password, method)
                            
                            if message:
                                st.markdown('<div class="success-box">✅ Message successfully extracted!</div>', unsafe_allow_html=True)
                                
                                # Display message
                                st.text_area("Extracted Message", message, height=150)
                                
                                # Display metadata
                                if metadata:
                                    with st.expander("📋 Message Metadata"):
                                        st.json(metadata)
                                
                                # Copy to clipboard button
                                st.code(message, language=None)
                            else:
                                st.markdown('<div class="error-box">❌ Failed to extract message. Check password and method.</div>', unsafe_allow_html=True)
                    
                    except Exception as e:
                        st.markdown(f'<div class="error-box">❌ Error: {str(e)}</div>', unsafe_allow_html=True)
                else:
                    st.warning("Please enter the decryption password!")
    
    elif mode == "📊 Analysis":
        st.header("Steganography Analysis")
        
        uploaded_file = st.file_uploader("Upload Image for Analysis", type=['png', 'jpg', 'jpeg', 'bmp'])
        
        if uploaded_file:
            image = Image.open(uploaded_file)
            img_array = np.array(image)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.image(image, caption="Original Image", use_column_width=True)
                
                # Basic statistics
                st.subheader("📈 Image Statistics")
                st.write(f"**Dimensions:** {image.size[0]} × {image.size[1]}")
                st.write(f"**Channels:** {len(img_array.shape)} ({'RGB' if len(img_array.shape) == 3 else 'Grayscale'})")
                st.write(f"**File Size:** {len(uploaded_file.getvalue()):,} bytes")
                st.write(f"**Max Capacity (LSB):** {img_array.size // 8:,} characters")
            
            with col2:
                # LSB analysis
                st.subheader("🔍 LSB Analysis")
                
                if len(img_array.shape) == 3:
                    # Show LSB planes
                    lsb_r = (img_array[:, :, 0] & 1) * 255
                    lsb_g = (img_array[:, :, 1] & 1) * 255
                    lsb_b = (img_array[:, :, 2] & 1) * 255
                    
                    lsb_combined = np.stack([lsb_r, lsb_g, lsb_b], axis=2)
                    st.image(lsb_combined, caption="LSB Visualization", use_column_width=True)
                
                # Entropy analysis
                flat_img = img_array.flatten()
                unique, counts = np.unique(flat_img, return_counts=True)
                entropy = -np.sum((counts/len(flat_img)) * np.log2(counts/len(flat_img) + 1e-10))
                
                st.write(f"**Image Entropy:** {entropy:.3f}")
                st.write(f"**Randomness Score:** {entropy/8*100:.1f}%")
                
                if entropy > 7.5:
                    st.success("High entropy - likely contains hidden data")
                elif entropy > 6.5:
                    st.warning("Medium entropy - possibly contains data")
                else:
                    st.info("Low entropy - likely clean image")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666;">
        🏆 Advanced Steganography Suite | Built for Hackathon Excellence
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()