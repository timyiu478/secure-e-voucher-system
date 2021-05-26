function validateForm(form){
  let isValid = true;

  let inputs = document.getElementsByClassName(`form-control ${form}`);
  let invalid_feedbacks = document.getElementsByClassName(`invalid-feedback ${form}`);  

  for(let i=0;i<inputs.length;i++){
    if(inputs[i].checkValidity() == false){
        isValid = false;
        invalid_feedbacks[i].classList.add("d-block");
      }
      else{
        invalid_feedbacks[i].classList.remove("d-block");
    }
  }

  if(form === 'authForm'){
    if(document.getElementById('sex').checkValidity()==false || document.getElementById('sex').value===""){
      isValid = false;
      document.getElementById('sex-fb').classList.add("d-block");
    }else{
      document.getElementById('sex-fb').classList.remove("d-block");
    }
  }
  
  if(form === 'registerForm'){
      let passwordRegisterInput = document.getElementById("passwordRegisterInput");
      let confirmPasswordRegisterInput = document.getElementById("confirmPasswordRegisterInput");
      if(passwordRegisterInput.value !== confirmPasswordRegisterInput.value){
        isValid = false;
        invalid_feedbacks[3].classList.add("d-block");
      }
  }

  return isValid;
}
