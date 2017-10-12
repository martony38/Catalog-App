function resizeImages() {
    // Resize images to keep 2:1 width to heigth ratio:
    $('.img-helper').each(function(index) {
        var imageWidth = $( this ).width();
        $( this ).css({
            'height': imageWidth / 2 + 'px'
        })
    });
};

$(resizeImages());

$( window ).resize(function() {
  resizeImages();
});