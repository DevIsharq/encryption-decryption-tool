document.addEventListener("DOMContentLoaded", function () {
    const fileInputs = document.querySelectorAll("input[type='file']");

    fileInputs.forEach(input => {
        input.addEventListener("change", function () {
            if (this.files.length > 0) {
                const fileName = this.files[0].name;
                this.nextElementSibling.textContent = fileName;
            }
        });
    });

    const flashMessages = document.querySelectorAll(".alert");
    setTimeout(() => {
        flashMessages.forEach(msg => msg.remove());
    }, 5000);

    document.querySelectorAll(".btn-download").forEach(button => {
        button.addEventListener("click", function () {
            const fileType = this.dataset.type;
            const fileName = this.dataset.filename;
            window.location.href = `/download/${fileType}/${fileName}`;
        });
    });
});