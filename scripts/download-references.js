const { refreshReferences } = require("../src/riskEngine");

refreshReferences()
  .then((result) => {
    console.log("Reference data refreshed");
    console.log(JSON.stringify(result, null, 2));
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
