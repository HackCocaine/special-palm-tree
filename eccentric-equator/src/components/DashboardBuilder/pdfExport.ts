import html2canvas from 'html2canvas';
import { jsPDF } from 'jspdf';

interface ExportOptions {
  title: string;
  filename?: string;
  includeHeader?: boolean;
  description?: string;
}

/**
 * Prepare edges for PDF export by disabling animations and applying static styles
 * Returns a cleanup function to restore original state
 */
function prepareEdgesForExport(canvasElement: HTMLElement): () => void {
  // Add export mode class to disable animations
  canvasElement.classList.add('pdf-export-mode');
  
  // Force a reflow to ensure styles are applied
  canvasElement.offsetHeight;
  
  // Return cleanup function
  return () => {
    canvasElement.classList.remove('pdf-export-mode');
  };
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

  // Prepare edges for export (disable animations)
  const cleanupExportMode = prepareEdgesForExport(canvasElement);

  try {
    // Wait for React to re-render with export mode styles
    await new Promise(resolve => setTimeout(resolve, 150));

    // Capture the canvas at high resolution
    const canvas = await html2canvas(canvasElement, {
      backgroundColor: '#0a0a0a',
      scale: 3, // High resolution for crisp output
      useCORS: true,
      allowTaint: true,
      logging: false,
      windowWidth: canvasElement.scrollWidth,
      windowHeight: canvasElement.scrollHeight,
      onclone: (clonedDoc) => {
        const clonedCanvas = clonedDoc.querySelector(canvasSelector) as HTMLElement;
        if (clonedCanvas) {
          // Apply export mode to cloned document as well
          clonedCanvas.classList.add('pdf-export-mode');
          
          // Hide controls, minimap, and attribution in export
          const controls = clonedCanvas.querySelector('.react-flow__controls');
          const minimap = clonedCanvas.querySelector('.react-flow__minimap');
          const attribution = clonedCanvas.querySelector('.react-flow__attribution');
          const quarterOverlay = clonedCanvas.querySelector('.viewer-quarter-columns, .quarter-columns');
          
          if (controls) (controls as HTMLElement).style.display = 'none';
          if (minimap) (minimap as HTMLElement).style.display = 'none';
          if (attribution) (attribution as HTMLElement).style.display = 'none';
          
          // Make quarter columns more visible for export
          if (quarterOverlay) {
            (quarterOverlay as HTMLElement).style.opacity = '1';
          }
          
          // Ensure all edges are visible in the cloned document
          const edges = clonedCanvas.querySelectorAll('.react-flow__edge path');
          edges.forEach((edge) => {
            const edgeEl = edge as SVGPathElement;
            edgeEl.style.strokeOpacity = '1';
            edgeEl.style.opacity = '1';
          });
        }
      }
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
      compress: true
    });

    // Set dark background
    pdf.setFillColor(10, 10, 10);
    pdf.rect(0, 0, pageWidth, pageHeight, 'F');
    
    // Header section
    let yOffset = 15;
    
    if (includeHeader) {
      // Brand accent line
      pdf.setDrawColor(0, 210, 106);
      pdf.setLineWidth(1);
      pdf.line(15, yOffset, 60, yOffset);
      
      // Title
      pdf.setFontSize(28);
      pdf.setTextColor(255, 255, 255);
      pdf.text(title, 15, yOffset + 12);
      
      // Subtitle with date
      pdf.setFontSize(11);
      pdf.setTextColor(138, 138, 138);
      const dateStr = new Date().toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
      pdf.text(`Q1 - Q4 Strategy Roadmap  •  Generated on ${dateStr}`, 15, yOffset + 20);
      
      // Branding on right side
      pdf.setFontSize(12);
      pdf.setTextColor(0, 210, 106);
      pdf.text('Hack', pageWidth - 55, yOffset + 8);
      pdf.setTextColor(255, 255, 255);
      pdf.text('fluency', pageWidth - 38, yOffset + 8);
      
      // Divider line
      pdf.setDrawColor(42, 42, 42);
      pdf.setLineWidth(0.5);
      pdf.line(15, yOffset + 28, pageWidth - 15, yOffset + 28);
      
      yOffset = 50;
    }

    // Calculate image dimensions to fit page while maintaining aspect ratio
    const availableWidth = pageWidth - 30; // margins
    const availableHeight = pageHeight - yOffset - 25; // header + footer margins
    
    const imgAspectRatio = canvas.width / canvas.height;
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
    
    // Add the high-quality canvas image
    pdf.addImage(
      canvas.toDataURL('image/png', 1.0),
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
    
    // Right footer - page branding
    pdf.setTextColor(0, 210, 106);
    pdf.text('hackfluency.com', pageWidth - 15, pageHeight - 10, { align: 'right' });

    // Save the PDF
    pdf.save(filename);

  } catch (error) {
    console.error('Error generating PDF:', error);
    alert('Failed to generate PDF. Please try again.');
  } finally {
    // Restore original edge animations and styles
    cleanupExportMode();
    // Remove loading overlay
    loadingOverlay.remove();
  }
}

