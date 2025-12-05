document.addEventListener('DOMContentLoaded', function () {
    const facultySelect = document.getElementById("faculty");
    const programmeSelect = document.getElementById("programme");
    const yearSelect = document.getElementById("year");
    const specWrapper = document.getElementById("specialization-wrapper");
    const specSelect = document.getElementById("specialization");

    const programmeLabels = window.PROGRAMME_LABELS || {};
    const specializationChoices = window.SPECIALIZATION_CHOICES || {};
    const currentProgramme = window.CURRENT_PROGRAMME || "";
    const currentSpec = window.CURRENT_SPEC || "";

    function updateProgramme() {
        const faculty = facultySelect.value;

        programmeSelect.innerHTML = "";
        const defaultOpt = document.createElement("option");
        defaultOpt.value = "";
        defaultOpt.textContent = "-- Choose one --";
        programmeSelect.appendChild(defaultOpt);

        const programmes = programmeLabels[faculty] || [];

        programmes.forEach(([value, label]) => {
            const opt = document.createElement("option");
            opt.value = value;
            opt.textContent = label;
            if (value === currentProgramme) {
                opt.selected = true;
            }
            programmeSelect.appendChild(opt);
        });
    }

    function updateSpecializations() {
        const fac = facultySelect.value;
        const prog = programmeSelect.value;
        const year = parseInt(yearSelect.value || "1", 10);

        const facSpecs = specializationChoices[fac] || {};
        const options = facSpecs[prog] || [];

        // BCS: only pick spec from Year 2 onwards
        const isBcs = (fac === "fci" && prog === "bcs");
        const needsSpec = options.length > 0 && (!isBcs || year >= 2);

        specSelect.innerHTML = "";
        const defaultOpt = document.createElement("option");
        defaultOpt.value = "";
        defaultOpt.textContent = "-- Choose one --";
        specSelect.appendChild(defaultOpt);

        if (!needsSpec) {
            specWrapper.style.display = "none";
            return;
        }

        options.forEach(([value, label]) => {
            const opt = document.createElement("option");
            opt.value = value;
            opt.textContent = label;
            if (value === currentSpec) {
                opt.selected = true;
            }
            specSelect.appendChild(opt);
        });

        specWrapper.style.display = "block";
    }

    facultySelect.addEventListener("change", function () {
        updateProgramme();
        updateSpecializations();
    });

    programmeSelect.addEventListener("change", updateSpecializations);
    yearSelect.addEventListener("change", updateSpecializations);

    // initial load 
    updateProgramme();
    updateSpecializations();
});
