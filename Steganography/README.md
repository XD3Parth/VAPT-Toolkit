# 🖼️ Steganography Online

Welcome to the Steganography Online project! This small project is dedicated to the art of steganography, providing functionality to **encode** a message in an image and to **decode** the message from the image.

Head over to the [GitHub page](https://parthxd7.github.io/Steganography/) to check out the online decoder and encoder.

## 📚 About Steganography

Steganography is the art of hiding a message inside another message. In this project, we hide a text message inside an image. An image will most likely go unnoticed, as not many people will suspect a hidden message inside an image.

Steganography is **not a means of encryption**, just a way of hiding data inside an image.

For more detailed information on Steganography, you can read the [Wikipedia article](http://en.wikipedia.org/wiki/Steganography).

## 🛠️ Implementation Details

1. **Normalization**: 
   - The user chooses an image, and the image data is then normalized. This means that each RGB value is decremented by one if it is not even. This is done for every pixel in the image.

2. **Message Conversion**:
   - The message is converted to a binary representation, with 8 bits per character. This binary representation is then applied to the normalized image, 3 bits per pixel. This means the maximum length of a message hidden in an image is:

   ```
   Image Width * Image Height * 3
   ------------------------------
               8
   ```

3. **Decoding**:
   - Since the image was normalized, we now know that an **even** r, g, or b value is **0** and an **odd** value is **1**. This is how the message is decoded back from the image.

## 🔒 Additional Layers of Security

Steganography is not a means of encryption but a way to hide data from plain sight. However, you can add layers of security by, for example, hiding a PGP encrypted message inside an image. So, even if the image does not go unnoticed, the message would still only be readable by the intended recipient.

---

Feel free to explore and contribute to this project! For any questions or suggestions, you can reach out via the issues section.

Happy Steganography! 🎉
