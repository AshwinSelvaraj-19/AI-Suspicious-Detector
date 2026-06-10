/* ===== PHOENIX — LANDING JS ===== */

/* ---- LIVE CLOCK ---- */
function updateClock() {
  const el = document.getElementById('live-clock');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toUTCString().split(' ')[4];
}
setInterval(updateClock, 1000);
updateClock();

/* ---- COUNTER ANIMATION ---- */
function animateCounter(el, target, decimals = 0, duration = 2000) {
  const start = performance.now();
  const update = (now) => {
    const t = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - t, 3);
    el.textContent = (target * ease).toFixed(decimals);
    if (t < 1) requestAnimationFrame(update);
    else el.textContent = target.toFixed(decimals);
  };
  requestAnimationFrame(update);
}

setTimeout(() => {
  document.querySelectorAll('.metric-val').forEach(el => {
    const target = parseFloat(el.dataset.target);
    const decimals = target % 1 !== 0 ? 1 : 0;
    animateCounter(el, target, decimals, 2200);
  });
}, 1400);

/* ---- PARTICLE CANVAS ---- */
(function initParticles() {
  const canvas = document.getElementById('particle-canvas');
  const ctx = canvas.getContext('2d');
  let W, H, particles = [], mouse = { x: -999, y: -999 };

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);
  window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });

  const COUNT = 90;
  for (let i = 0; i < COUNT; i++) {
    particles.push({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.5,
      alpha: Math.random() * 0.5 + 0.1
    });
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 140) {
          ctx.beginPath();
          ctx.strokeStyle = `rgba(255, 107, 53, ${0.12 * (1 - dist / 140)})`;
          ctx.lineWidth = 0.5;
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
      // Mouse connections
      const mdx = particles[i].x - mouse.x;
      const mdy = particles[i].y - mouse.y;
      const md = Math.sqrt(mdx * mdx + mdy * mdy);
      if (md < 180) {
        ctx.beginPath();
        ctx.strokeStyle = `rgba(255, 107, 53, ${0.25 * (1 - md / 180)})`;
        ctx.lineWidth = 0.8;
        ctx.moveTo(particles[i].x, particles[i].y);
        ctx.lineTo(mouse.x, mouse.y);
        ctx.stroke();
      }
    }

    // Draw dots
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(255, 107, 53, ${p.alpha})`;
      ctx.fill();
    });

    // Update
    particles.forEach(p => {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0) p.x = W;
      if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H;
      if (p.y > H) p.y = 0;
    });

    requestAnimationFrame(draw);
  }
  draw();
})();

/* ---- THREE.JS HOLOGRAPHIC SHIELD ---- */
(function initThree() {
  if (typeof THREE === 'undefined') return;

  const container = document.getElementById('three-container');
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(window.devicePixelRatio);
  renderer.setSize(window.innerWidth, window.innerHeight);
  renderer.setClearColor(0x000000, 0);
  container.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(50, window.innerWidth / window.innerHeight, 0.1, 100);
  camera.position.set(0, 0, 6);

  // Ambient
  scene.add(new THREE.AmbientLight(0x1a0500, 2));
  const pLight = new THREE.PointLight(0xff6b35, 3, 20);
  pLight.position.set(0, 2, 3);
  scene.add(pLight);

  // SHIELD SHAPE (custom pentagon-like)
  const shieldShape = new THREE.Shape();
  shieldShape.moveTo(0, 2.2);
  shieldShape.bezierCurveTo(1.6, 2.2, 2.2, 1.4, 2.2, 0.4);
  shieldShape.bezierCurveTo(2.2, -1.0, 1.2, -2.0, 0, -2.5);
  shieldShape.bezierCurveTo(-1.2, -2.0, -2.2, -1.0, -2.2, 0.4);
  shieldShape.bezierCurveTo(-2.2, 1.4, -1.6, 2.2, 0, 2.2);

  const shieldGeo = new THREE.ShapeGeometry(shieldShape, 64);
  const shieldMat = new THREE.MeshBasicMaterial({
    color: 0xff6b35,
    transparent: true,
    opacity: 0.03,
    side: THREE.DoubleSide
  });
  const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
  scene.add(shieldMesh);

  // Shield wireframe edges
  const edges = new THREE.EdgesGeometry(shieldGeo);
  const edgeMat = new THREE.LineBasicMaterial({
    color: 0xff6b35, transparent: true, opacity: 0.5
  });
  scene.add(new THREE.LineSegments(edges, edgeMat));

  // Inner glow ring
  const ringGeo = new THREE.TorusGeometry(1.6, 0.008, 8, 80);
  const ringMat = new THREE.MeshBasicMaterial({ color: 0xff2e00, transparent: true, opacity: 0.6 });
  const ring1 = new THREE.Mesh(ringGeo, ringMat);
  scene.add(ring1);

  const ring2Geo = new THREE.TorusGeometry(2.0, 0.005, 8, 80);
  const ring2Mat = new THREE.MeshBasicMaterial({ color: 0xff6b35, transparent: true, opacity: 0.3 });
  const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
  ring2.rotation.x = 0.4;
  scene.add(ring2);

  // Scan line plane
  const scanGeo = new THREE.PlaneGeometry(4.5, 0.06);
  const scanMat = new THREE.MeshBasicMaterial({
    color: 0xff6b35, transparent: true, opacity: 0.6, side: THREE.DoubleSide
  });
  const scanLine = new THREE.Mesh(scanGeo, scanMat);
  scene.add(scanLine);

  // Floating particles around shield
  const pGeo = new THREE.BufferGeometry();
  const pCount = 200;
  const pPos = new Float32Array(pCount * 3);
  const pAngles = new Float32Array(pCount);
  const pRadii = new Float32Array(pCount);
  const pSpeeds = new Float32Array(pCount);
  const pY = new Float32Array(pCount);
  for (let i = 0; i < pCount; i++) {
    pAngles[i] = Math.random() * Math.PI * 2;
    pRadii[i] = 2.5 + Math.random() * 2;
    pSpeeds[i] = (Math.random() * 0.3 + 0.1) * (Math.random() < 0.5 ? 1 : -1);
    pY[i] = (Math.random() - 0.5) * 5;
    pPos[i * 3] = Math.cos(pAngles[i]) * pRadii[i];
    pPos[i * 3 + 1] = pY[i];
    pPos[i * 3 + 2] = Math.sin(pAngles[i]) * pRadii[i] * 0.3;
  }
  pGeo.setAttribute('position', new THREE.BufferAttribute(pPos, 3));
  const pMat = new THREE.PointsMaterial({ color: 0xff6b35, size: 0.04, transparent: true, opacity: 0.7 });
  const pCloud = new THREE.Points(pGeo, pMat);
  scene.add(pCloud);

  let scanY = -2.5;
  let frame = 0;
  const clock = new THREE.Clock();

  function animate() {
    requestAnimationFrame(animate);
    const t = clock.getElapsedTime();
    frame++;

    // Rotate shield slightly
    shieldMesh.rotation.y = Math.sin(t * 0.3) * 0.15;
    if (shieldMesh.children) {
      shieldMesh.children.forEach(c => c.rotation.y = shieldMesh.rotation.y);
    }

    // Pulse rings
    ring1.rotation.z = t * 0.2;
    ring2.rotation.z = -t * 0.15;
    ring1.scale.setScalar(1 + Math.sin(t * 1.2) * 0.02);

    // Scan line
    scanY += 0.015;
    if (scanY > 2.5) scanY = -2.5;
    scanLine.position.y = scanY;
    scanMat.opacity = 0.3 + Math.sin(t * 3) * 0.2;

    // Float particles
    const positions = pCloud.geometry.attributes.position.array;
    for (let i = 0; i < pCount; i++) {
      pAngles[i] += 0.003 * pSpeeds[i];
      positions[i * 3] = Math.cos(pAngles[i]) * pRadii[i];
      positions[i * 3 + 1] = pY[i] + Math.sin(t * 0.5 + i) * 0.1;
      positions[i * 3 + 2] = Math.sin(pAngles[i]) * pRadii[i] * 0.3;
    }
    pCloud.geometry.attributes.position.needsUpdate = true;

    // Pulse glow
    edgeMat.opacity = 0.3 + Math.sin(t * 0.8) * 0.2;
    pLight.intensity = 2 + Math.sin(t * 1.5) * 1;

    renderer.render(scene, camera);
  }
  animate();

  window.addEventListener('resize', () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
  });

  // Mouse parallax
  document.addEventListener('mousemove', e => {
    const nx = (e.clientX / window.innerWidth - 0.5) * 0.4;
    const ny = (e.clientY / window.innerHeight - 0.5) * 0.3;
    shieldMesh.rotation.y = nx;
    shieldMesh.rotation.x = -ny * 0.5;
    ring1.rotation.y = nx * 0.5;
  });
})();

/* ---- INTERSECTION OBSERVER FOR FEATURES ---- */
const observer = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (e.isIntersecting) e.target.classList.add('visible');
  });
}, { threshold: 0.15 });

document.querySelectorAll('.feat-card').forEach(el => observer.observe(el));