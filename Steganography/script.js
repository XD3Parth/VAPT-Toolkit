$(document).ready(function() {
  $('button.encode, button.decode').click(event => event.preventDefault());

  $('input[name=decodeFile]').change(previewDecodeImage);
  $('input[name=baseFile]').change(previewEncodeImage);

  function previewDecodeImage() {
    const file = document.querySelector('input[name=decodeFile]').files[0];
    previewImage(file, ".decode canvas", () => $(".decode").fadeIn());
  }

  function previewEncodeImage() {
    const file = document.querySelector("input[name=baseFile]").files[0];
    $(".images .nulled, .images .message").hide();
    previewImage(file, ".original canvas", () => {
      $(".images .original, .images").fadeIn();
    });
  }

  function previewImage(file, canvasSelector, callback) {
    const reader = new FileReader();
    const image = new Image();
    const $canvas = $(canvasSelector);
    const context = $canvas[0].getContext('2d');

    if (file) {
      reader.readAsDataURL(file);
    }

    reader.onloadend = () => {
      image.src = URL.createObjectURL(file);
      image.onload = () => {
        $canvas.prop({ width: image.width, height: image.height });
        context.drawImage(image, 0, 0);
        callback();
      };
    };
  }

  function encodeMessage() {
    $(".error, .binary").hide();

    const text = $("textarea.message").val();
    const $originalCanvas = $('.original canvas');
    const $nulledCanvas = $('.nulled canvas');
    const $messageCanvas = $('.message canvas');
    const originalContext = $originalCanvas[0].getContext("2d");
    const nulledContext = $nulledCanvas[0].getContext("2d");
    const messageContext = $messageCanvas[0].getContext("2d");
    const width = $originalCanvas[0].width;
    const height = $originalCanvas[0].height;

    if ((text.length * 8) > (width * height * 3)) {
      $(".error").text("Text too long for chosen image...").fadeIn();
      return;
    }

    $nulledCanvas.prop({ width, height });
    $messageCanvas.prop({ width, height });

    const original = originalContext.getImageData(0, 0, width, height);
    const pixel = original.data;

    for (let i = 0; i < pixel.length; i += 4) {
      for (let offset = 0; offset < 3; offset++) {
        if (pixel[i + offset] % 2 !== 0) {
          pixel[i + offset]--;
        }
      }
    }
    nulledContext.putImageData(original, 0, 0);

    const binaryMessage = text.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join('');
    $('.binary textarea').text(binaryMessage);

    const message = nulledContext.getImageData(0, 0, width, height);
    let counter = 0;

    for (let i = 0; i < message.data.length && counter < binaryMessage.length; i += 4) {
      for (let offset = 0; offset < 3 && counter < binaryMessage.length; offset++) {
        message.data[i + offset] += parseInt(binaryMessage[counter++], 2);
      }
    }
    messageContext.putImageData(message, 0, 0);

    $(".binary, .images .nulled, .images .message").fadeIn();
  }

  function decodeMessage() {
    const $originalCanvas = $('.decode canvas');
    const originalContext = $originalCanvas[0].getContext("2d");
    const width = $originalCanvas[0].width;
    const height = $originalCanvas[0].height;

    const original = originalContext.getImageData(0, 0, width, height);
    const binaryMessage = [...original.data].reduce((acc, byte, i) => {
      if (i % 4 !== 3) acc.push(byte % 2);
      return acc;
    }, []).join('');

    const output = binaryMessage.match(/.{1,8}/g).map(byte => String.fromCharCode(parseInt(byte, 2))).join('');

    $('.binary-decode textarea').text(output);
    $('.binary-decode').fadeIn();
  }

  // Attach encode and decode functions to buttons
  $('button.encode').click(encodeMessage);
  $('button.decode').click(decodeMessage);
});
