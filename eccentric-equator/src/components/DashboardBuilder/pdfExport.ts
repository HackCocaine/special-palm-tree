import { toPng, toBlob } from 'html-to-image';
import { jsPDF } from 'jspdf';

interface ExportOptions {
  title: string;
  filename?: string;
  includeHeader?: boolean;
  description?: string;
}

/**
 * Export a dashboard canvas to high-quality PDF
 * Full landscape layout optimized for client presentations
 */
export async function exportDashboardToPDF(
  canvasSelector: string,
  options: ExportOptions
): Promise<void> {
  const { 
    title, 
    filename = 'strategy-roadmap.pdf', 
    includeHeader = true,
    description = ''
  } = options;

  // Find the canvas element
  const canvasElement = document.querySelector(canvasSelector) as HTMLElement;
  if (!canvasElement) {
    console.error('Canvas element not found');
    alert('Unable to generate PDF. Canvas not found.');
    return;
  }

  // Show loading overlay with spinner
  const loadingOverlay = document.createElement('div');
  loadingOverlay.id = 'pdf-export-loading';
  loadingOverlay.innerHTML = `
    <div style="display: flex; flex-direction: column; align-items: center; gap: 20px;">
      <div style="
        width: 50px;
        height: 50px;
        border: 4px solid rgba(255,255,255,0.2);
        border-top-color: #00D26A;
        border-radius: 50%;
        animation: spin 1s linear infinite;
      "></div>
      <p style="font-size: 16px; margin: 0;">Generating high-quality PDF...</p>
      <p style="font-size: 12px; color: #888; margin: 0;">This may take a few seconds</p>
    </div>
    <style>
      @keyframes spin {
        to { transform: rotate(360deg); }
      }
    </style>
  `;
  loadingOverlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.9);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10000;
    color: white;
    font-family: 'Inter', system-ui, sans-serif;
  `;
  document.body.appendChild(loadingOverlay);

  // Add export mode class to prepare for capture
  canvasElement.classList.add('pdf-export-mode');
  
  // Force layout recalculation
  canvasElement.offsetHeight;

  try {
    // Wait for React to re-render with export mode styles and SVG to be ready
    await new Promise(resolve => setTimeout(resolve, 800));
    
    // Find the react-flow wrapper to ensure we capture the correct bounds
    const reactFlowWrapper = canvasElement.querySelector('.react-flow') as HTMLElement;
    const targetElement = reactFlowWrapper || canvasElement;
    
    // Get the actual bounds of the content including edges
    const edgesContainer = canvasElement.querySelector('.react-flow__edges') as HTMLElement;
    const nodesContainer = canvasElement.querySelector('.react-flow__nodes') as HTMLElement;
    
    // Temporarily ensure edges are visible at the SVG level
    if (edgesContainer) {
      const svg = edgesContainer.querySelector('svg');
      if (svg) {
        svg.style.overflow = 'visible';
        svg.setAttribute('overflow', 'visible');
        
        // Ensure all path elements have explicit attributes for capture
        const paths = svg.querySelectorAll('path');
        paths.forEach((path, index) => {
          // Get current computed styles
          const computedStyle = window.getComputedStyle(path);
          const stroke = computedStyle.stroke;
          const strokeWidth = computedStyle.strokeWidth;
          const strokeDasharray = computedStyle.strokeDasharray;
          
          // Set explicit SVG attributes (these serialize better than CSS)
          if (stroke && stroke !== 'none') {
            path.setAttribute('stroke', stroke);
          }
          if (strokeWidth && strokeWidth !== '0px') {
            path.setAttribute('stroke-width', strokeWidth);
          }
          if (strokeDasharray && strokeDasharray !== 'none') {
            path.setAttribute('stroke-dasharray', strokeDasharray);
          }
          
          // Ensure fill is none for edge paths
          path.setAttribute('fill', 'none');
          
          // Remove any opacity animations
          path.style.opacity = '1';
          path.style.strokeOpacity = '1';
          path.style.animation = 'none';
          
          // Add debug logging for first few edges
          if (index < 3) {
            console.log(`Edge ${index}: stroke=${stroke}, width=${strokeWidth}, dash=${strokeDasharray}`);
          }
        });
      }
    }
    
    // Also ensure nodes are visible
    if (nodesContainer) {
      nodesContainer.style.opacity = '1';
      nodesContainer.style.visibility = 'visible';
    }
    
    // Wait a bit more for SVG changes to apply
    await new Promise(resolve => setTimeout(resolve, 300));

    // Capture using html-to-image (much better SVG support than html2canvas)
    const dataUrl = await toPng(targetElement, {
      backgroundColor: '#0a0a0a',
      pixelRatio: 2, // High resolution for crisp output
      cacheBust: true,
      skipFonts: false,
      includeQueryParams: true,
      filter: (node) => {
        // Filter out controls and other UI elements we don't want in the PDF
        if (node.classList) {
          if (node.classList.contains('react-flow__controls') ||
              node.classList.contains('react-flow__minimap') ||
              node.classList.contains('react-flow__attribution')) {
            return false;
          }
        }
        return true;
      },
    });

    // Use larger page format for better quality
    // A3 landscape gives more room for detail
    const pageWidth = 420; // A3 landscape width in mm
    const pageHeight = 297; // A3 landscape height in mm
    
    // Create PDF with A3 landscape
    const pdf = new jsPDF({
      orientation: 'landscape',
      unit: 'mm',
      format: 'a3',
      compress: true,
      putOnlyUsedFonts: true,
    });

    pdf.setProperties({
      title: title || 'Security Strategy Roadmap',
      subject: 'Q1-Q4 Cybersecurity Strategy Roadmap',
      author: 'Hackfluency',
      creator: 'Hackfluency Strategy Dashboard',
      keywords: 'cybersecurity, strategy, roadmap, security planning',
      creationDate: new Date(),
    });

    const logoImg = new Image();
    logoImg.crossOrigin = 'anonymous';
    const logoDataUrl = await new Promise<string>((resolve, reject) => {
      logoImg.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = logoImg.width;
        canvas.height = logoImg.height;
        const ctx = canvas.getContext('2d');
        if (ctx) {
          ctx.drawImage(logoImg, 0, 0);
          resolve(canvas.toDataURL('image/png'));
        } else {
          reject(new Error('Failed to get canvas context'));
        }
      };
      logoImg.onerror = () => reject(new Error('Failed to load logo'));
      logoImg.src = '/HFNeon.png';
    });

    pdf.setFillColor(10, 10, 10);
    pdf.rect(0, 0, pageWidth, pageHeight, 'F');
    
    let yOffset = 15;
    
    if (includeHeader) {
      const logoSize = 20;
      pdf.addImage(logoDataUrl, 'PNG', 15, yOffset - 5, logoSize, logoSize);
      
      pdf.setDrawColor(0, 210, 106);
      pdf.setLineWidth(1);
      pdf.line(40, yOffset, 85, yOffset);
      
      // Title
      pdf.setFontSize(28);
      pdf.setTextColor(255, 255, 255);
      pdf.text(title, 40, yOffset + 12);
      
      pdf.setFontSize(11);
      pdf.setTextColor(138, 138, 138);
      const dateStr = new Date().toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
      pdf.text(`Q1 - Q4 Strategy Roadmap  •  Generated on ${dateStr}`, 40, yOffset + 20);
      
      pdf.setFontSize(12);
      pdf.setTextColor(0, 210, 106);
      pdf.text('Hackfluency', pageWidth - 55, yOffset + 8);
      
      // Divider line
      pdf.setDrawColor(42, 42, 42);
      pdf.setLineWidth(0.5);
      pdf.line(15, yOffset + 28, pageWidth - 15, yOffset + 28);
      
      yOffset = 50;
    }

    // Calculate image dimensions to fit page while maintaining aspect ratio
    const img = new Image();
    await new Promise((resolve, reject) => {
      img.onload = resolve;
      img.onerror = reject;
      img.src = dataUrl;
    });
    
    const availableWidth = pageWidth - 30; // margins
    const availableHeight = pageHeight - yOffset - 25; // header + footer margins
    
    const imgAspectRatio = img.width / img.height;
    const pageAspectRatio = availableWidth / availableHeight;
    
    let imgWidth, imgHeight;
    
    if (imgAspectRatio > pageAspectRatio) {
      // Image is wider - fit to width
      imgWidth = availableWidth;
      imgHeight = availableWidth / imgAspectRatio;
    } else {
      // Image is taller - fit to height
      imgHeight = availableHeight;
      imgWidth = availableHeight * imgAspectRatio;
    }
    
    // Center the image horizontally
    const xOffset = (pageWidth - imgWidth) / 2;
    
    // Add the high-quality image
    pdf.addImage(
      dataUrl,
      'PNG',
      xOffset,
      yOffset,
      imgWidth,
      imgHeight
    );

    // Footer
    pdf.setFontSize(9);
    pdf.setTextColor(100, 100, 100);
    
    // Left footer - quarters legend
    pdf.text('Q1: Jan-Mar  |  Q2: Apr-Jun  |  Q3: Jul-Sep  |  Q4: Oct-Dec', 15, pageHeight - 10);
    
    // Center footer
    pdf.text(
      'Security Strategy Roadmap - Confidential',
      pageWidth / 2,
      pageHeight - 10,
      { align: 'center' }
    );
    
    pdf.setTextColor(0, 210, 106);
    pdf.text('hackfluency.com', pageWidth - 15, pageHeight - 10, { align: 'right' });
    
    pdf.setFontSize(8);
    pdf.setTextColor(80, 80, 80);
    pdf.text('© 2026 Hackfluency. All rights reserved.', pageWidth / 2, pageHeight - 5, { align: 'center' });

    // Save the PDF
    pdf.save(filename);

  } catch (error) {
    console.error('Error generating PDF:', error);
    alert('Failed to generate PDF. Please try again.');
  } finally {
    // Restore original state
    canvasElement.classList.remove('pdf-export-mode');
    // Remove loading overlay
    loadingOverlay.remove();
  }
}
