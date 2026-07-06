(function(){
  function closeAll() {
    document.querySelectorAll('.dropdown-menu').forEach(m => m.classList.add('hidden'));
    document.querySelectorAll('.chev').forEach(c => c.classList.remove('open'));
  }

  document.addEventListener('click', function(e){
    const btn = e.target.closest('.user-chip-button');
    if (btn) {
      const container = btn.closest('.user-chip');
      const menu = container.querySelector('.dropdown-menu');
      const chev = container.querySelector('.chev');
      const isHidden = menu.classList.contains('hidden');
      closeAll();
      if (isHidden) {
        menu.classList.remove('hidden');
        if (chev) chev.classList.add('open');
      }
      return;
    }
    // click outside
    if (!e.target.closest('.user-chip')) {
      closeAll();
    }
  });
})();
