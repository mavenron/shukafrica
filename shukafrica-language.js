// ShukAfrica Global Language System

const shukAfricaTranslations = {
  en: {
    language: "Language",
    pageTitle: "ShukAfrica — West Africa, connected",
    pageDescription: "ShukAfrica — West Africa, connected. Buy, sell, rent, deliver and find nearby emergency services.",
    english: "English",
    french: "Français",
    trustedMarketplace: "Your trusted marketplace",
    heroBuySellRent: "Buy. Sell. Rent.",
    heroDescription: "ShukAfrica connects people, products and services across Ghana, Côte d’Ivoire, Burkina Faso and Togo — faster, safer and easier.",
    exploreMarketplace: "Explore marketplace",
exploreServices: "Explore services",
heroDeliverExpress: "Deliver. Express.",
heroGetHelp: "Get Help. Stay Safe.",
    createAccount: "Create Your ShukAfrica Account",
    chooseAccount: "Choose Account Type",
    customer: "Customer",
    business: "Business",
    riderDriver: "Rider / Driver",

    free: "FREE",
    registrationFee: "Registration Fee",
    fullName: "Full Name",
    businessName: "Full Name / Business Name",
    phoneNumber: "Phone Number",
    email: "Email",
    password: "Password",
    country: "Country",
    selectCountry: "Select country",

    vehicleType: "Vehicle Type",
    selectVehicle: "Select vehicle type",
    vehicleNumber: "Vehicle Number / Number Plate",
    insuranceNumber: "Insurance Number",
    driversLicence: "Driver's Licence",

    businessVerification: "Business Verification Video",
    businessVerificationText: "Record a short video showing yourself at or inside your place of business.",

    licenceText: "Upload a clear picture of your driver's licence.",

    customerRegistration: "Customer Registration",
    businessRegistration: "Business Registration",
    riderRegistration: "Rider / Driver Registration",

    continuePayment: "CONTINUE TO PAYMENT",
    createCustomer: "CREATE CUSTOMER ACCOUNT",

    alreadyAccount: "Already have an account?",
    signIn: "Sign in",
    backHome: "← Back to ShukAfrica",

    customerFree: "Customer registration is free.",
    businessFee: "GHS 20",
    riderFee: "GHS 20",

    chooseAccountIntro: "Choose the account that best describes how you will use ShukAfrica.",

    businessProtection: "To help protect ShukAfrica users from fake businesses and scammers, Business accounts require a short verification video.",

    riderProtection: "Rider and Driver accounts require verification before they can accept delivery jobs."
  },

  fr: {
    language: "Langue",
    pageTitle: "ShukAfrica — L'Afrique de l'Ouest, connectée",
    pageDescription: "ShukAfrica — L'Afrique de l'Ouest, connectée. Achetez, vendez, louez, livrez et trouvez les services d'urgence à proximité.",
    english: "English",
    french: "Français",
    trustedMarketplace: "Votre marché de confiance",
    heroBuySellRent: "Achetez. Vendez. Louez.",
heroDeliverExpress: "Livrez. Express.",
heroGetHelp: "Obtenez de l'aide. Restez en sécurité.",
    heroDescription: "ShukAfrica connecte les personnes, les produits et les services à travers le Ghana, la Côte d’Ivoire, le Burkina Faso et le Togo — plus rapidement, plus sûrement et plus facilement.",
    createAccount: "Créer votre compte ShukAfrica",
    chooseAccount: "Choisissez le type de compte",
    customer: "Client",
    business: "Entreprise",
    riderDriver: "Livreur / Conducteur",

    free: "GRATUIT",
    registrationFee: "Frais d'inscription",
    fullName: "Nom complet",
    businessName: "Nom complet / Nom de l'entreprise",
    phoneNumber: "Numéro de téléphone",
    email: "E-mail",
    password: "Mot de passe",
    country: "Pays",
    selectCountry: "Sélectionnez le pays",

    vehicleType: "Type de véhicule",
    selectVehicle: "Sélectionnez le type de véhicule",
    vehicleNumber: "Numéro du véhicule / Plaque d'immatriculation",
    insuranceNumber: "Numéro d'assurance",
    driversLicence: "Permis de conduire",

    businessVerification: "Vidéo de vérification de l'entreprise",
    businessVerificationText: "Enregistrez une courte vidéo de vous-même dans ou devant votre lieu d'activité.",

    licenceText: "Téléchargez une photo claire de votre permis de conduire.",

    customerRegistration: "Inscription client",
    businessRegistration: "Inscription entreprise",
    riderRegistration: "Inscription livreur / conducteur",

    continuePayment: "CONTINUER VERS LE PAIEMENT",
    createCustomer: "CRÉER UN COMPTE CLIENT",

    alreadyAccount: "Vous avez déjà un compte ?",
    signIn: "Se connecter",
    backHome: "← Retour à ShukAfrica",

    customerFree: "L'inscription client est gratuite.",
    businessFee: "20 GHS",
    riderFee: "20 GHS",

    chooseAccountIntro: "Choisissez le type de compte qui correspond le mieux à votre utilisation de ShukAfrica.",

    businessProtection: "Pour aider à protéger les utilisateurs de ShukAfrica contre les fausses entreprises et les escrocs, les comptes professionnels nécessitent une courte vidéo de vérification.",

    riderProtection: "Les comptes de livreur et de conducteur doivent être vérifiés avant de pouvoir accepter des livraisons."
  }
};

function shukAfricaGetLanguage() {
  return localStorage.getItem("shukafrica_language") || "en";
}

function shukAfricaSetLanguage(language) {
  if (!shukAfricaTranslations[language]) {
    return;
  }

  localStorage.setItem("shukafrica_language", language);
  shukAfricaApplyLanguage(language);
}

function shukAfricaApplyLanguage(language) {
  const translations = shukAfricaTranslations[language];

  if (!translations) {
    return;
  }

  document.documentElement.lang = language;
  document.title = translations.pageTitle;

  const description = document.querySelector('meta[name="description"]');
  if (description) {
    description.setAttribute("content", translations.pageDescription);
  }

  // Translate standard inner text and input values
  document.querySelectorAll("[data-i18n]").forEach(element => {
    const key = element.dataset.i18n;

    if (translations[key]) {
      if (element.tagName === "INPUT" && (element.type === "submit" || element.type === "button")) {
        element.value = translations[key];
      } else {
        element.textContent = translations[key];
      }
    }
  });

  // Translate input placeholders
  document.querySelectorAll("[data-i18n-placeholder]").forEach(element => {
    const key = element.dataset.i18nPlaceholder;

    if (translations[key]) {
      element.placeholder = translations[key];
    }
  });
}

function shukAfricaChangeLanguage() {
  const currentLanguage = shukAfricaGetLanguage();
  const newLanguage = currentLanguage === "fr" ? "en" : "fr";
  shukAfricaSetLanguage(newLanguage);
}

function shukAfricaShowLanguageChoice() {
  if (document.getElementById("shukAfricaLanguageBox")) {
    return;
  }

  const box = document.createElement("div");
  box.id = "shukAfricaLanguageBox";

  box.innerHTML = `
    <div style="
      position:fixed;
      inset:0;
      background:rgba(0,0,0,.75);
      display:flex;
      align-items:center;
      justify-content:center;
      z-index:99999;
      padding:20px;
    ">
      <div style="
        width:min(420px,100%);
        background:#101d1e;
        border:1px solid #263738;
        border-radius:18px;
        padding:25px;
        text-align:center;
        color:#fff;
      ">
        <div style="font-size:35px;margin-bottom:10px;">🌍</div>
        <h2 style="margin:0 0 8px;">Choose Your Language</h2>
        <p style="color:#a8b6b3;font-size:13px;margin-bottom:20px;">
          Choisissez votre langue
        </p>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
          <button
            type="button"
            onclick="shukAfricaSetLanguage('en'); document.getElementById('shukAfricaLanguageBox').remove();"
            style="padding:14px;border-radius:12px;border:1px solid #ffb52e;background:#29200d;color:#fff;font-weight:bold;cursor:pointer;"
          >
            🇬🇧 English
          </button>

          <button
            type="button"
            onclick="shukAfricaSetLanguage('fr'); document.getElementById('shukAfricaLanguageBox').remove();"
            style="padding:14px;border-radius:12px;border:1px solid #1688db;background:#10222c;color:#fff;font-weight:bold;cursor:pointer;"
          >
            🇫🇷 Français
          </button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(box);
}

document.addEventListener("DOMContentLoaded", function() {
  const hasSavedLanguage = localStorage.getItem("shukafrica_language");
  const currentLanguage = shukAfricaGetLanguage();

  // Always apply current language to clear initial default HTML state
  shukAfricaApplyLanguage(currentLanguage);

  // If user hasn't chosen before, prompt them
  if (!hasSavedLanguage) {
    shukAfricaShowLanguageChoice();
  }

  const languageBtn = document.getElementById("languageBtn");
  if (languageBtn) {
    languageBtn.addEventListener("click", function() {
      shukAfricaShowLanguageChoice();
    });
  }
});
    
