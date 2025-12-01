/**
 * @fileoverview Gemini AI Service - Handles interaction with Google Gemini API
 * Provides functionality to generate meeting summaries from chat messages.
 * @author Connectify Team
 * @version 1.0.0
 */

import { GoogleGenerativeAI } from '@google/generative-ai';

/**
 * Interface for chat messages used in summary generation
 */
interface ChatMessage {
  user: string;
  text: string;
  time: string;
}

/**
 * Interface for the generated summary
 */
interface MeetingSummary {
  summary: string;
  keyPoints: string[];
  participants: string[];
  timestamp: string;
}

/**
 * Gemini AI Service class
 * Handles all interactions with Google Gemini API for generating summaries
 */
class GeminiService {
  private genAI: GoogleGenerativeAI;
  private model: any;

  constructor() {
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      console.warn('⚠️ GEMINI_API_KEY is not configured. AI summaries will not work until configured.');
      return;
    }

    this.genAI = new GoogleGenerativeAI(apiKey);
    this.model = this.genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });
    console.log('✅ Gemini AI service initialized successfully');
  }

  /**
   * Generates a summary from chat messages using Gemini AI
   * @param {ChatMessage[]} messages - Array of chat messages
   * @param {string} meetingId - The ID of the meeting
   * @returns {Promise<MeetingSummary>} The generated summary
   */
  async generateMeetingSummary(messages: ChatMessage[], meetingId: string): Promise<MeetingSummary> {
    if (!this.model || !this.genAI) {
      throw new Error('Gemini AI service is not properly configured. Please set GEMINI_API_KEY in environment variables.');
    }

    try {
      // Format messages for the prompt
      const chatHistory = messages
        .map(msg => `[${new Date(msg.time).toLocaleTimeString()}] ${msg.user}: ${msg.text}`)
        .join('\n');

      // Extract unique participants
      const participants = [...new Set(messages.map(msg => msg.user))];

      // Create the prompt for Gemini
      const prompt = `
Analiza la siguiente conversación de una reunión virtual y genera un resumen estructurado en español.

CONVERSACIÓN:
${chatHistory}

Por favor, proporciona:
1. Un resumen general de la reunión (2-3 oraciones)
2. Los puntos clave discutidos (máximo 5 puntos, en formato de lista)

Responde ÚNICAMENTE en formato JSON con esta estructura exacta:
{
  "summary": "resumen general aquí",
  "keyPoints": ["punto 1", "punto 2", "punto 3"]
}

No incluyas ningún texto adicional fuera del JSON.
`;

      // Generate content using Gemini
      console.log('🤖 Generating summary with Gemini AI...');
      const result = await this.model.generateContent(prompt);
      const response = await result.response;
      const text = response.text();

      console.log('📄 Gemini response received');

      // Parse the JSON response
      let parsedResponse;
      try {
        // Try to extract JSON from the response
        const jsonMatch = text.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          parsedResponse = JSON.parse(jsonMatch[0]);
        } else {
          parsedResponse = JSON.parse(text);
        }
      } catch (parseError) {
        console.error('Error parsing Gemini response:', parseError);
        // Fallback: create a basic summary
        parsedResponse = {
          summary: 'Se llevó a cabo una reunión con intercambio de mensajes entre los participantes.',
          keyPoints: ['Comunicación entre participantes', 'Intercambio de información']
        };
      }

      const summary: MeetingSummary = {
        summary: parsedResponse.summary || 'No se pudo generar un resumen.',
        keyPoints: parsedResponse.keyPoints || [],
        participants: participants,
        timestamp: new Date().toISOString()
      };

      console.log('✅ Summary generated successfully');
      return summary;

    } catch (error) {
      console.error('❌ Error generating summary with Gemini:', error);
      throw new Error(`Failed to generate summary: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Validates if the service is properly configured
   * @returns {boolean} True if the service is ready to use
   */
  isConfigured(): boolean {
    return !!process.env.GEMINI_API_KEY;
  }
}

// Export singleton instance
export default new GeminiService();
